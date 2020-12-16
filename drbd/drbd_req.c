// SPDX-License-Identifier: GPL-2.0-or-later
/*
   drbd_req.c

   This file is part of DRBD by Philipp Reisner and Lars Ellenberg.

   Copyright (C) 2001-2008, LINBIT Information Technologies GmbH.
   Copyright (C) 1999-2008, Philipp Reisner <philipp.reisner@linbit.com>.
   Copyright (C) 2002-2008, Lars Ellenberg <lars.ellenberg@linbit.com>.


 */

#include <linux/module.h>

#include <linux/slab.h>
#include <linux/drbd.h>
#include "drbd_int.h"
#include "drbd_req.h"



static bool drbd_may_do_local_read(struct drbd_device *device, sector_t sector, int size);

static struct drbd_request *drbd_req_new(struct drbd_device *device, struct bio *bio_src)
{
	struct drbd_request *req;

	req = mempool_alloc(&drbd_request_mempool, GFP_NOIO);
	if (!req)
		return NULL;

	memset(req, 0, sizeof(*req));

	kref_get(&device->kref);
	kref_debug_get(&device->kref_debug, 6);

	req->device = device;
	req->master_bio = bio_src;
	req->epoch = 0;

	drbd_clear_interval(&req->i);
	req->i.sector = bio_src->bi_iter.bi_sector;
	req->i.size = bio_src->bi_iter.bi_size;
	req->i.local = true;
	req->i.waiting = false;

	INIT_LIST_HEAD(&req->tl_requests);
	INIT_LIST_HEAD(&req->req_pending_master_completion);
	INIT_LIST_HEAD(&req->req_pending_local);

	/* one reference to be put by __drbd_make_request */
	atomic_set(&req->completion_ref, 1);
	/* one kref as long as completion_ref > 0 */
	kref_init(&req->kref);

	req->local_rq_state = (bio_data_dir(bio_src) == WRITE ? RQ_WRITE : 0)
	              | (bio_op(bio_src) == REQ_OP_WRITE_SAME ? RQ_WSAME : 0)
	              | (bio_op(bio_src) == REQ_OP_WRITE_ZEROES ? RQ_ZEROES : 0)
	              | (bio_op(bio_src) == REQ_OP_DISCARD ? RQ_UNMAP : 0);

	return req;
}

static void req_destroy_no_send_peer_ack(struct kref *kref)
{
	struct drbd_request *req = container_of(kref, struct drbd_request, kref);
	mempool_free(req, &drbd_request_mempool);
}

void drbd_queue_peer_ack(struct drbd_resource *resource, struct drbd_request *req)
{
	struct drbd_connection *connection;
	bool queued = false;

	refcount_set(&req->kref.refcount, 1); /* was 0, instead of kref_get() */
	rcu_read_lock();
	for_each_connection_rcu(connection, resource) {
		unsigned int node_id = connection->peer_node_id;
		if (connection->agreed_pro_version < 110 ||
		    connection->cstate[NOW] != C_CONNECTED ||
		    !(req->net_rq_state[node_id] & RQ_NET_SENT))
			continue;
		kref_get(&req->kref);
		req->net_rq_state[node_id] |= RQ_PEER_ACK;
		if (!queued) {
			list_add_tail(&req->tl_requests, &resource->peer_ack_list);
			queued = true;
		}
		queue_work(connection->ack_sender, &connection->peer_ack_work);
	}
	rcu_read_unlock();

	kref_put(&req->kref, req_destroy_no_send_peer_ack);
}

static bool peer_ack_differs(struct drbd_request *req1, struct drbd_request *req2)
{
	unsigned int max_node_id = req1->device->resource->max_node_id;
	unsigned int node_id;

	for (node_id = 0; node_id <= max_node_id; node_id++)
		if ((req1->net_rq_state[node_id] & RQ_NET_OK) !=
		    (req2->net_rq_state[node_id] & RQ_NET_OK))
			return true;
	return false;
}

static bool peer_ack_window_full(struct drbd_request *req)
{
	struct drbd_resource *resource = req->device->resource;
	u32 peer_ack_window = resource->res_opts.peer_ack_window;
	u64 last_dagtag = resource->last_peer_acked_dagtag + peer_ack_window;

	return dagtag_newer_eq(req->dagtag_sector, last_dagtag);
}

static void drbd_remove_request_interval(struct rb_root *root,
					 struct drbd_request *req)
{
	struct drbd_device *device = req->device;
	struct drbd_interval *i = &req->i;

	drbd_remove_interval(root, i);

	/* Wake up any processes waiting for this request to complete.  */
	if (i->waiting)
		wake_up(&device->misc_wait);
}

/* must_hold resource->req_lock */
void drbd_req_destroy(struct kref *kref)
{
	struct drbd_request *req = container_of(kref, struct drbd_request, kref);
	struct drbd_request *destroy_next;
	struct drbd_device *device;
	struct drbd_peer_device *peer_device;
	unsigned int s;
	bool was_last_ref;

 tail_recursion:
	was_last_ref = false;
	device = req->device;
	s = req->local_rq_state;
	destroy_next = req->destroy_next;

#ifdef CONFIG_DRBD_TIMING_STATS
	if (s & RQ_WRITE) {
		unsigned long flags;

		spin_lock_irqsave(&device->timing_lock, flags);
		device->reqs++;
		ktime_aggregate(device, req, in_actlog_kt);
		ktime_aggregate(device, req, pre_submit_kt);
		for_each_peer_device(peer_device, device) {
			int node_id = peer_device->node_id;
			unsigned ns = drbd_req_state_by_peer_device(req, peer_device);
			if (!(ns & RQ_NET_MASK))
				continue;
			ktime_aggregate_pd(peer_device, node_id, req, pre_send_kt);
			ktime_aggregate_pd(peer_device, node_id, req, acked_kt);
			ktime_aggregate_pd(peer_device, node_id, req, net_done_kt);
		}
		spin_unlock_irqrestore(&device->timing_lock, flags);
	}
#endif

	/* paranoia */
	for_each_peer_device(peer_device, device) {
		unsigned ns = drbd_req_state_by_peer_device(req, peer_device);
		if (!(ns & RQ_NET_MASK))
			continue;
		if (ns & RQ_NET_DONE)
			continue;

		drbd_err(device,
			"drbd_req_destroy: Logic BUG rq_state: (0:%x, %d:%x), completion_ref = %d\n",
			s, 1 + peer_device->node_id, ns, atomic_read(&req->completion_ref));
		return;
	}

	/* more paranoia */
	if ((req->master_bio && !(s & RQ_POSTPONED)) ||
		atomic_read(&req->completion_ref) || (s & RQ_LOCAL_PENDING)) {
		drbd_err(device, "drbd_req_destroy: Logic BUG rq_state: %x, completion_ref = %d\n",
				s, atomic_read(&req->completion_ref));
		return;
	}

	list_del_init(&req->tl_requests);

	/* finally remove the request from the conflict detection
	 * respective block_id verification interval tree. */
	if (!drbd_interval_empty(&req->i)) {
		struct rb_root *root;

		if (s & RQ_WRITE)
			root = &device->write_requests;
		else
			root = &device->read_requests;
		drbd_remove_request_interval(root, req);
	} else if (s & (RQ_NET_MASK & ~RQ_NET_DONE) && req->i.size != 0)
		drbd_err(device, "drbd_req_destroy: Logic BUG: interval empty, but: rq_state=0x%x, sect=%llu, size=%u\n",
			s, (unsigned long long)req->i.sector, req->i.size);

	if (s & RQ_WRITE) {
		/* There is a special case:
		 * we may notice late that IO was suspended,
		 * and postpone, or schedule for retry, a write,
		 * before it even was submitted or sent.
		 * In that case we do not want to touch the bitmap at all.
		 */
		if ((s & (RQ_POSTPONED|RQ_LOCAL_MASK|RQ_NET_MASK)) != RQ_POSTPONED &&
		    req->i.size && get_ldev_if_state(device, D_DETACHING)) {
			struct drbd_peer_md *peer_md = device->ldev->md.peers;
			unsigned long bits = -1, mask = -1;
			int node_id, max_node_id = device->resource->max_node_id;

			for (node_id = 0; node_id <= max_node_id; node_id++) {
				unsigned int net_rq_state;

				net_rq_state = req->net_rq_state[node_id];
				if (net_rq_state & RQ_NET_OK) {
					int bitmap_index = peer_md[node_id].bitmap_index;

					if (bitmap_index == -1)
						continue;

					if (net_rq_state & RQ_NET_SIS)
						clear_bit(bitmap_index, &bits);
					else
						clear_bit(bitmap_index, &mask);
				}
			}
			drbd_set_sync(device, req->i.sector, req->i.size, bits, mask);
			put_ldev(device);
		}

		/* one might be tempted to move the drbd_al_complete_io
		 * to the local io completion callback drbd_request_endio.
		 * but, if this was a mirror write, we may only
		 * drbd_al_complete_io after this is RQ_NET_DONE,
		 * otherwise the extent could be dropped from the al
		 * before it has actually been written on the peer.
		 * if we crash before our peer knows about the request,
		 * but after the extent has been dropped from the al,
		 * we would forget to resync the corresponding extent.
		 */
		if (s & RQ_IN_ACT_LOG) {
			if (get_ldev_if_state(device, D_DETACHING)) {
				was_last_ref = drbd_al_complete_io(device, &req->i);
				put_ldev(device);
			} else if (drbd_ratelimit()) {
				drbd_warn(device, "Should have called drbd_al_complete_io(, %llu, %u), "
					  "but my Disk seems to have failed :(\n",
					  (unsigned long long) req->i.sector, req->i.size);

			}
		}
	}

	if (s & RQ_WRITE && req->i.size) {
		struct drbd_resource *resource = device->resource;
		struct drbd_request *peer_ack_req = resource->peer_ack_req;

		if (peer_ack_req) {
			if (peer_ack_differs(req, peer_ack_req) ||
			    (was_last_ref && atomic_read(&device->ap_actlog_cnt)) ||
			    peer_ack_window_full(req)) {
				drbd_queue_peer_ack(resource, peer_ack_req);
				peer_ack_req = NULL;
			} else
				mempool_free(peer_ack_req, &drbd_request_mempool);
		}
		req->device = NULL;
		resource->peer_ack_req = req;
		mod_timer(&resource->peer_ack_timer,
			  jiffies + resource->res_opts.peer_ack_delay * HZ / 1000);

		if (!peer_ack_req)
			resource->last_peer_acked_dagtag = req->dagtag_sector;
	} else
		mempool_free(req, &drbd_request_mempool);

	/* In both branches of the if above, the reference to device gets released */
	kref_debug_put(&device->kref_debug, 6);
	kref_put(&device->kref, drbd_destroy_device);

	/*
	 * Do the equivalent of:
	 *   kref_put(&req->kref, drbd_req_destroy)
	 * without recursing into the destructor.
	 */
	if (destroy_next) {
		req = destroy_next;
		if (refcount_dec_and_test(&req->kref.refcount))
			goto tail_recursion;
	}
}

static void wake_all_senders(struct drbd_resource *resource) {
	struct drbd_connection *connection;
	/* We need make sure any update is visible before we wake up the
	 * threads that may check the values in their wait_event() condition.
	 * Do we need smp_mb here? Or rather switch to atomic_t? */
	rcu_read_lock();
	for_each_connection_rcu(connection, resource)
		wake_up(&connection->sender_work.q_wait);
	rcu_read_unlock();
}

/* must hold resource->req_lock */
bool start_new_tl_epoch(struct drbd_resource *resource)
{
	/* no point closing an epoch, if it is empty, anyways. */
	if (resource->current_tle_writes == 0)
		return false;

	resource->current_tle_writes = 0;
	atomic_inc(&resource->current_tle_nr);
	wake_all_senders(resource);
	return true;
}

void complete_master_bio(struct drbd_device *device,
		struct bio_and_error *m)
{
	int rw = bio_data_dir(m->bio);
	m->bio->bi_status = errno_to_blk_status(m->error);
	bio_endio(m->bio);
	dec_ap_bio(device, rw);
}


/* Helper for __req_mod().
 * Set m->bio to the master bio, if it is fit to be completed,
 * or leave it alone (it is initialized to NULL in __req_mod),
 * if it has already been completed, or cannot be completed yet.
 * If m->bio is set, the error status to be returned is placed in m->error.
 */
static
void drbd_req_complete(struct drbd_request *req, struct bio_and_error *m)
{
	const unsigned s = req->local_rq_state;
	struct drbd_device *device = req->device;
	struct drbd_peer_device *peer_device;
	int error, ok = 0;

	/*
	 * figure out whether to report success or failure.
	 *
	 * report success when at least one of the operations succeeded.
	 * or, to put the other way,
	 * only report failure, when both operations failed.
	 *
	 * what to do about the failures is handled elsewhere.
	 * what we need to do here is just: complete the master_bio.
	 *
	 * local completion error, if any, has been stored as ERR_PTR
	 * in private_bio within drbd_request_endio.
	 */
	if (s & RQ_LOCAL_OK)
		++ok;
	error = PTR_ERR(req->private_bio);

	for_each_peer_device(peer_device, device) {
		unsigned ns = drbd_req_state_by_peer_device(req, peer_device);
		/* any net ok ok local ok is good enough to complete this bio as OK */
		if (ns & RQ_NET_OK)
			++ok;
		/* paranoia */
		/* we must not complete the master bio, while it is
		 *	still being processed by _drbd_send_zc_bio (drbd_send_dblock),
		 *	respectively still needed for the second drbd_csum_bio() there.
		 *	not yet acknowledged by the peer
		 *	not yet completed by the local io subsystem
		 * these flags may get cleared in any order by
		 *	the worker,
		 *	the sender,
		 *	the receiver,
		 *	the bio_endio completion callbacks.
		 */
		if (!(ns & RQ_NET_MASK))
			continue;
		if (!(ns & (RQ_NET_PENDING|RQ_NET_QUEUED)))
			continue;

		drbd_err(device,
			"drbd_req_complete: Logic BUG rq_state: (0:%x, %d:%x), completion_ref = %d\n",
			 s, 1 + peer_device->node_id, ns, atomic_read(&req->completion_ref));
		return;
	}

	/* more paranoia */
	if (atomic_read(&req->completion_ref) ||
	    ((s & RQ_LOCAL_PENDING) && !(s & RQ_LOCAL_ABORTED))) {
		drbd_err(device, "drbd_req_complete: Logic BUG rq_state: %x, completion_ref = %d\n",
				s, atomic_read(&req->completion_ref));
		return;
	}

	if (!req->master_bio) {
		drbd_err(device, "drbd_req_complete: Logic BUG, master_bio == NULL!\n");
		return;
	}

	/* Before we can signal completion to the upper layers,
	 * we may need to close the current transfer log epoch.
	 * We are within the request lock, so we can simply compare
	 * the request epoch number with the current transfer log
	 * epoch number.  If they match, increase the current_tle_nr,
	 * and reset the transfer log epoch write_cnt.
	 */
	if (bio_data_dir(req->master_bio) == WRITE &&
	    req->epoch == atomic_read(&device->resource->current_tle_nr))
		start_new_tl_epoch(device->resource);

	/* Update disk stats */
	bio_end_io_acct(req->master_bio, req->start_jif);

	/* If READ failed,
	 * have it be pushed back to the retry work queue,
	 * so it will re-enter __drbd_make_request(),
	 * and be re-assigned to a suitable local or remote path,
	 * or failed if we do not have access to good data anymore.
	 *
	 * Unless it was failed early by __drbd_make_request(),
	 * because no path was available, in which case
	 * it was not even added to the transfer_log.
	 *
	 * read-ahead may fail, and will not be retried.
	 *
	 * WRITE should have used all available paths already.
	 */
	if (!ok &&
	    bio_op(req->master_bio) == REQ_OP_READ &&
	    !(req->master_bio->bi_opf & REQ_RAHEAD) &&
	    !list_empty(&req->tl_requests))
		req->local_rq_state |= RQ_POSTPONED;

	if (!(req->local_rq_state & RQ_POSTPONED)) {
		struct drbd_resource *resource = device->resource;
		bool quorum =
			resource->res_opts.on_no_quorum == ONQ_IO_ERROR ?
			resource->cached_all_devices_have_quorum : true;

		m->error = ok && quorum ? 0 : (error ?: -EIO);
		m->bio = req->master_bio;
		req->master_bio = NULL;
		/* We leave it in the tree, to be able to verify later
		 * write-acks in protocol != C during resync.
		 * But we mark it as "complete", so it won't be counted as
		 * conflict in a multi-primary setup. */
		req->i.completed = true;
	}

	if (req->i.waiting)
		wake_up(&device->misc_wait);

	/* Either we are about to complete to upper layers,
	 * or we will restart this request.
	 * In either case, the request object will be destroyed soon,
	 * so better remove it from all lists. */
	list_del_init(&req->req_pending_master_completion);
}

/* still holds resource->req_lock */
static void drbd_req_put_completion_ref(struct drbd_request *req, struct bio_and_error *m, int put)
{
	D_ASSERT(req->device, m || (req->local_rq_state & RQ_POSTPONED));

	if (!put)
		return;

	if (!atomic_sub_and_test(put, &req->completion_ref))
		return;

	drbd_req_complete(req, m);

	/* local completion may still come in later,
	 * we need to keep the req object around. */
	if (req->local_rq_state & RQ_LOCAL_ABORTED)
		return;

	if (req->local_rq_state & RQ_POSTPONED) {
		/* don't destroy the req object just yet,
		 * but queue it for retry */
		drbd_restart_request(req);
		return;
	}

	kref_put(&req->kref, drbd_req_destroy);
}

static void set_if_null_req_next(struct drbd_peer_device *peer_device, struct drbd_request *req)
{
	struct drbd_connection *connection = peer_device ? peer_device->connection : NULL;
	if (!connection)
		return;
	if (connection->todo.req_next == NULL)
		connection->todo.req_next = req;
}

static void advance_conn_req_next(struct drbd_peer_device *peer_device, struct drbd_request *req)
{
	struct drbd_connection *connection = peer_device ? peer_device->connection : NULL;
	if (!connection)
		return;
	if (connection->todo.req_next != req)
		return;
	list_for_each_entry_continue(req, &connection->resource->transfer_log, tl_requests) {
		const unsigned s = drbd_req_state_by_peer_device(req, peer_device);
		if (s & RQ_NET_QUEUED)
			break;
	}
	if (&req->tl_requests == &connection->resource->transfer_log)
		req = NULL;
	connection->todo.req_next = req;
}

static void set_if_null_req_ack_pending(struct drbd_peer_device *peer_device, struct drbd_request *req)
{
	struct drbd_connection *connection = peer_device ? peer_device->connection : NULL;
	if (!connection)
		return;
	if (connection->req_ack_pending == NULL)
		connection->req_ack_pending = req;
}

static void advance_conn_req_ack_pending(struct drbd_peer_device *peer_device, struct drbd_request *req)
{
	struct drbd_connection *connection = peer_device ? peer_device->connection : NULL;
	if (!connection)
		return;
	if (connection->req_ack_pending != req)
		return;
	list_for_each_entry_continue(req, &connection->resource->transfer_log, tl_requests) {
		const unsigned s = drbd_req_state_by_peer_device(req, peer_device);
		if ((s & RQ_NET_SENT) && (s & RQ_NET_PENDING))
			break;
	}
	if (&req->tl_requests == &connection->resource->transfer_log)
		req = NULL;
	connection->req_ack_pending = req;
}

static void set_if_null_req_not_net_done(struct drbd_peer_device *peer_device, struct drbd_request *req)
{
	struct drbd_connection *connection = peer_device ? peer_device->connection : NULL;
	if (!connection)
		return;
	if (connection->req_not_net_done == NULL)
		connection->req_not_net_done = req;
}

static void advance_conn_req_not_net_done(struct drbd_peer_device *peer_device, struct drbd_request *req)
{
	struct drbd_connection *connection = peer_device ? peer_device->connection : NULL;
	if (!connection)
		return;
	if (connection->req_not_net_done != req)
		return;
	list_for_each_entry_continue(req, &connection->resource->transfer_log, tl_requests) {
		const unsigned s = drbd_req_state_by_peer_device(req, peer_device);
		if ((s & RQ_NET_SENT) && !(s & RQ_NET_DONE))
			break;
	}
	if (&req->tl_requests == &connection->resource->transfer_log)
		req = NULL;
	connection->req_not_net_done = req;
}

/* for wsame, discard, and zero-out requests, the payload (amount of data we
 * need to send) is much smaller than the number of storage sectors affected */
static unsigned int req_payload_sectors(struct drbd_request *req)
{
	/* actually: physical_block_size,
	 * but lets just hardcode 4k in sectors: */
	if (unlikely(req->local_rq_state & RQ_WSAME))
		return 8;
	/* really only a few bytes, but let's pretend one sector */
	if (unlikely(req->local_rq_state & (RQ_UNMAP|RQ_ZEROES)))
		return 1;
	/* other have all the data as payload on the wire */
	return req->i.size >> 9;
}

/* I'd like this to be the only place that manipulates
 * req->completion_ref and req->kref. */
static void mod_rq_state(struct drbd_request *req, struct bio_and_error *m,
		struct drbd_peer_device *peer_device,
		int clear, int set)
{
	unsigned old_net = 0;
	unsigned old_local = req->local_rq_state;
	unsigned set_local = set & RQ_STATE_0_MASK;
	unsigned clear_local = clear & RQ_STATE_0_MASK;
	int c_put = 0;
	const int idx = peer_device ? peer_device->node_id : -1;

	set &= ~RQ_STATE_0_MASK;
	clear &= ~RQ_STATE_0_MASK;

	if (idx == -1) {
		/* do not try to manipulate net state bits
		 * without an associated state slot! */
		BUG_ON(set);
		BUG_ON(clear);
	}

	if (drbd_suspended(req->device) && !((old_local | clear_local) & RQ_COMPLETION_SUSP))
		set_local |= RQ_COMPLETION_SUSP;

	/* apply */

	req->local_rq_state &= ~clear_local;
	req->local_rq_state |= set_local;

	if (idx != -1) {
		old_net = req->net_rq_state[idx];
		req->net_rq_state[idx] &= ~clear;
		req->net_rq_state[idx] |= set;
	}


	/* no change? */
	if (req->local_rq_state == old_local &&
	    (idx == -1 || req->net_rq_state[idx] == old_net))
		return;

	/* intent: get references */

	kref_get(&req->kref);

	if (!(old_local & RQ_LOCAL_PENDING) && (set_local & RQ_LOCAL_PENDING))
		atomic_inc(&req->completion_ref);

	if (!(old_net & RQ_NET_PENDING) && (set & RQ_NET_PENDING)) {
		inc_ap_pending(peer_device);
		atomic_inc(&req->completion_ref);
	}

	if (!(old_net & RQ_NET_QUEUED) && (set & RQ_NET_QUEUED)) {
		atomic_inc(&req->completion_ref);
		set_if_null_req_next(peer_device, req);
	}

	if (!(old_net & RQ_EXP_BARR_ACK) && (set & RQ_EXP_BARR_ACK))
		kref_get(&req->kref); /* wait for the DONE */

	if (!(old_net & RQ_NET_SENT) && (set & RQ_NET_SENT)) {
		/* potentially already completed in the ack_receiver thread */
		if (!(old_net & RQ_NET_DONE)) {
			atomic_add(req_payload_sectors(req), &peer_device->connection->ap_in_flight);
			set_if_null_req_not_net_done(peer_device, req);
		}
		if (req->net_rq_state[idx] & RQ_NET_PENDING)
			set_if_null_req_ack_pending(peer_device, req);
	}

	if (!(old_local & RQ_COMPLETION_SUSP) && (set_local & RQ_COMPLETION_SUSP))
		atomic_inc(&req->completion_ref);

	/* progress: put references */

	if ((old_local & RQ_COMPLETION_SUSP) && (clear_local & RQ_COMPLETION_SUSP))
		++c_put;

	if (!(old_local & RQ_LOCAL_ABORTED) && (set_local & RQ_LOCAL_ABORTED)) {
		D_ASSERT(req->device, req->local_rq_state & RQ_LOCAL_PENDING);
		++c_put;
	}

	if ((old_local & RQ_LOCAL_PENDING) && (clear_local & RQ_LOCAL_PENDING)) {
		if (req->local_rq_state & RQ_LOCAL_ABORTED)
			kref_put(&req->kref, drbd_req_destroy);
		else
			++c_put;
		list_del_init(&req->req_pending_local);
	}

	if ((old_net & RQ_NET_PENDING) && (clear & RQ_NET_PENDING)) {
		dec_ap_pending(peer_device);
		++c_put;
		ktime_get_accounting(req->acked_kt[peer_device->node_id]);
		advance_conn_req_ack_pending(peer_device, req);
	}

	if ((old_net & RQ_NET_QUEUED) && (clear & RQ_NET_QUEUED)) {
		++c_put;
		advance_conn_req_next(peer_device, req);
	}

	if (!(old_net & RQ_NET_DONE) && (set & RQ_NET_DONE)) {
		atomic_t *ap_in_flight = &peer_device->connection->ap_in_flight;

		if (old_net & RQ_NET_SENT)
			atomic_sub(req_payload_sectors(req), ap_in_flight);
		if (old_net & RQ_EXP_BARR_ACK)
			kref_put(&req->kref, drbd_req_destroy);
		ktime_get_accounting(req->net_done_kt[peer_device->node_id]);

		if (peer_device->repl_state[NOW] == L_AHEAD &&
		    atomic_read(ap_in_flight) == 0) {
			struct drbd_peer_device *pd;
			int vnr;
			/* The first peer device to notice that it is time to
			 * go Ahead -> SyncSource tries to trigger that
			 * transition for *all* peer devices currently in
			 * L_AHEAD for this connection. */
			idr_for_each_entry(&peer_device->connection->peer_devices, pd, vnr) {
				if (pd->repl_state[NOW] != L_AHEAD)
					continue;
				if (test_and_set_bit(AHEAD_TO_SYNC_SOURCE, &pd->flags))
					continue; /* already done */
				pd->start_resync_side = L_SYNC_SOURCE;
				pd->start_resync_timer.expires = jiffies + HZ;
				add_timer(&pd->start_resync_timer);
			}
		}

		/* in ahead/behind mode, or just in case,
		 * before we finally destroy this request,
		 * the caching pointers must not reference it anymore */
		advance_conn_req_next(peer_device, req);
		advance_conn_req_ack_pending(peer_device, req);
		advance_conn_req_not_net_done(peer_device, req);
	}

	/* potentially complete and destroy */

	/* If we made progress, retry conflicting peer requests, if any. */
	if (req->i.waiting)
		wake_up(&req->device->misc_wait);

	drbd_req_put_completion_ref(req, m, c_put);
	kref_put(&req->kref, drbd_req_destroy);
}

static void drbd_report_io_error(struct drbd_device *device, struct drbd_request *req)
{
        char b[BDEVNAME_SIZE];

	if (!drbd_ratelimit())
		return;

	drbd_warn(device, "local %s IO error sector %llu+%u on %s\n",
		  (req->local_rq_state & RQ_WRITE) ? "WRITE" : "READ",
		  (unsigned long long)req->i.sector,
		  req->i.size >> 9,
		  bdevname(device->ldev->backing_bdev, b));
}

/* Helper for HANDED_OVER_TO_NETWORK.
 * Is this a protocol A write (neither WRITE_ACK nor RECEIVE_ACK expected)?
 * Is it also still "PENDING"?
 * --> If so, clear PENDING and set NET_OK below.
 * If it is a protocol A write, but not RQ_PENDING anymore, neg-ack was faster
 * (and we must not set RQ_NET_OK) */
static inline bool is_pending_write_protocol_A(struct drbd_request *req, int idx)
{
	return (req->local_rq_state & RQ_WRITE) == 0 ? 0 :
		(req->net_rq_state[idx] &
		   (RQ_NET_PENDING|RQ_EXP_WRITE_ACK|RQ_EXP_RECEIVE_ACK))
		==  RQ_NET_PENDING;
}

/* obviously this could be coded as many single functions
 * instead of one huge switch,
 * or by putting the code directly in the respective locations
 * (as it has been before).
 *
 * but having it this way
 *  enforces that it is all in this one place, where it is easier to audit,
 *  it makes it obvious that whatever "event" "happens" to a request should
 *  happen "atomically" within the req_lock,
 *  and it enforces that we have to think in a very structured manner
 *  about the "events" that may happen to a request during its life time ...
 *
 *
 * peer_device == NULL means local disk
 */
void __req_mod(struct drbd_request *req, enum drbd_req_event what,
		struct drbd_peer_device *peer_device,
		struct bio_and_error *m)
{
	struct drbd_device *device = req->device;
	struct net_conf *nc;
	int p;
	int idx;

	if (m)
		m->bio = NULL;

	idx = peer_device ? peer_device->node_id : -1;

	switch (what) {
	default:
		drbd_err(device, "LOGIC BUG in %s:%u\n", __FILE__ , __LINE__);
		break;

	/* does not happen...
	 * initialization done in drbd_req_new
	case CREATED:
		break;
		*/

	case TO_BE_SENT: /* via network */
		/* reached via __drbd_make_request
		 * and from w_read_retry_remote */
		D_ASSERT(device, !(req->net_rq_state[idx] & RQ_NET_MASK));
		rcu_read_lock();
		nc = rcu_dereference(peer_device->connection->transport.net_conf);
		p = nc->wire_protocol;
		rcu_read_unlock();
		req->net_rq_state[idx] |=
			p == DRBD_PROT_C ? RQ_EXP_WRITE_ACK :
			p == DRBD_PROT_B ? RQ_EXP_RECEIVE_ACK : 0;
		mod_rq_state(req, m, peer_device, 0, RQ_NET_PENDING);
		break;

	case TO_BE_SUBMITTED: /* locally */
		/* reached via __drbd_make_request */
		D_ASSERT(device, !(req->local_rq_state & RQ_LOCAL_MASK));
		mod_rq_state(req, m, peer_device, 0, RQ_LOCAL_PENDING);
		break;

	case COMPLETED_OK:
		if (req->local_rq_state & RQ_WRITE)
			device->writ_cnt += req->i.size >> 9;
		else
			device->read_cnt += req->i.size >> 9;

		mod_rq_state(req, m, peer_device, RQ_LOCAL_PENDING,
				RQ_LOCAL_COMPLETED|RQ_LOCAL_OK);
		break;

	case ABORT_DISK_IO:
		mod_rq_state(req, m, peer_device, 0, RQ_LOCAL_ABORTED);
		break;

	case WRITE_COMPLETED_WITH_ERROR:
		drbd_report_io_error(device, req);
		__drbd_chk_io_error(device, DRBD_WRITE_ERROR);
		mod_rq_state(req, m, peer_device, RQ_LOCAL_PENDING, RQ_LOCAL_COMPLETED);
		break;

	case READ_COMPLETED_WITH_ERROR:
		drbd_set_all_out_of_sync(device, req->i.sector, req->i.size);
		drbd_report_io_error(device, req);
		__drbd_chk_io_error(device, DRBD_READ_ERROR);
		fallthrough;
	case READ_AHEAD_COMPLETED_WITH_ERROR:
		/* it is legal to fail read-ahead, no __drbd_chk_io_error in that case. */
		mod_rq_state(req, m, peer_device, RQ_LOCAL_PENDING, RQ_LOCAL_COMPLETED);
		break;

	case DISCARD_COMPLETED_NOTSUPP:
	case DISCARD_COMPLETED_WITH_ERROR:
		/* I'd rather not detach from local disk just because it
		 * failed a REQ_OP_DISCARD. */
		mod_rq_state(req, m, peer_device, RQ_LOCAL_PENDING, RQ_LOCAL_COMPLETED);
		break;

	case QUEUE_FOR_NET_READ:
		/* READ, and
		 * no local disk,
		 * or target area marked as invalid,
		 * or just got an io-error. */
		/* from __drbd_make_request
		 * or from bio_endio during read io-error recovery */

		/* So we can verify the handle in the answer packet.
		 * Corresponding drbd_remove_request_interval is in
		 * drbd_req_complete() */
		D_ASSERT(device, drbd_interval_empty(&req->i));
		drbd_insert_interval(&device->read_requests, &req->i);

		set_bit(UNPLUG_REMOTE, &device->flags);

		D_ASSERT(device, req->net_rq_state[idx] & RQ_NET_PENDING);
		D_ASSERT(device, (req->local_rq_state & RQ_LOCAL_MASK) == 0);
		mod_rq_state(req, m, peer_device, 0, RQ_NET_QUEUED);
		break;

	case QUEUE_FOR_NET_WRITE:
		/* assert something? */
		/* from __drbd_make_request only */

		/* NOTE
		 * In case the req ended up on the transfer log before being
		 * queued on the worker, it could lead to this request being
		 * missed during cleanup after connection loss.
		 * So we have to do both operations here,
		 * within the same lock that protects the transfer log.
		 *
		 * _req_add_to_epoch(req); this has to be after the
		 * _maybe_start_new_epoch(req); which happened in
		 * __drbd_make_request, because we now may set the bit
		 * again ourselves to close the current epoch.
		 *
		 * Add req to the (now) current epoch (barrier). */

		/* otherwise we may lose an unplug, which may cause some remote
		 * io-scheduler timeout to expire, increasing maximum latency,
		 * hurting performance. */
		set_bit(UNPLUG_REMOTE, &device->flags);

		/* queue work item to send data */
		D_ASSERT(device, req->net_rq_state[idx] & RQ_NET_PENDING);
		mod_rq_state(req, m, peer_device, 0, RQ_NET_QUEUED|RQ_EXP_BARR_ACK);

		/* Close the epoch, in case it outgrew the limit.
		 * Or if this is a "batch bio", and some of our peers is "old",
		 * because a batch bio "storm" (like, large scale discarding
		 * during mkfs time) would be likely to starve out the peers
		 * activity log, if it is smaller than ours (or we don't have
		 * any).  And a fix for the resulting potential distributed
		 * deadlock was only implemented with P_CONFIRM_STABLE with
		 * protocol version 114.
		 */
		if (device->resource->cached_min_aggreed_protocol_version < 114 &&
		    (req->local_rq_state & (RQ_UNMAP|RQ_WSAME|RQ_ZEROES)))
			p = 1;
		else {
			rcu_read_lock();
			nc = rcu_dereference(peer_device->connection->transport.net_conf);
			p = nc->max_epoch_size;
			rcu_read_unlock();
		}
		if (device->resource->current_tle_writes >= p)
			start_new_tl_epoch(device->resource);
		break;

	case QUEUE_FOR_SEND_OOS:
		mod_rq_state(req, m, peer_device, 0, RQ_NET_QUEUED);
		break;

	case READ_RETRY_REMOTE_CANCELED:
	case SEND_CANCELED:
	case SEND_FAILED:
		/* Just update flags so it is no longer marked as on the sender
		 * queue; real cleanup will be done from
		 * tl_walk(,CONNECTION_LOST_WHILE_PENDING). */
		mod_rq_state(req, m, peer_device, RQ_NET_QUEUED, 0);
		break;

	case HANDED_OVER_TO_NETWORK:
		/* assert something? */
		if (is_pending_write_protocol_A(req, idx))
			/* this is what is dangerous about protocol A:
			 * pretend it was successfully written on the peer. */
			mod_rq_state(req, m, peer_device, RQ_NET_QUEUED|RQ_NET_PENDING,
				     RQ_NET_SENT|RQ_NET_OK);
		else
			mod_rq_state(req, m, peer_device, RQ_NET_QUEUED, RQ_NET_SENT);
		/* It is still not yet RQ_NET_DONE until the
		 * corresponding epoch barrier got acked as well,
		 * so we know what to dirty on connection loss. */
		break;

	case OOS_HANDED_TO_NETWORK:
		/* Was not set PENDING, no longer QUEUED, so is now DONE
		 * as far as this connection is concerned. */
		mod_rq_state(req, m, peer_device, RQ_NET_QUEUED, RQ_NET_DONE);
		break;

	case CONNECTION_LOST_WHILE_PENDING:
		/* transfer log cleanup after connection loss */
		mod_rq_state(req, m, peer_device,
				RQ_NET_OK|RQ_NET_PENDING|RQ_COMPLETION_SUSP,
				RQ_NET_DONE);
		break;

	case DISCARD_WRITE:
		/* for discarded conflicting writes of multiple primaries,
		 * there is no need to keep anything in the tl, potential
		 * node crashes are covered by the activity log.
		 *
		 * If this request had been marked as RQ_POSTPONED before,
		 * it will actually not be discarded, but "restarted",
		 * resubmitted from the retry worker context. */
		D_ASSERT(device, req->net_rq_state[idx] & RQ_NET_PENDING);
		D_ASSERT(device, req->net_rq_state[idx] & RQ_EXP_WRITE_ACK);
		mod_rq_state(req, m, peer_device, RQ_NET_PENDING, RQ_NET_DONE|RQ_NET_OK);
		break;

	case WRITE_ACKED_BY_PEER_AND_SIS:
		req->net_rq_state[idx] |= RQ_NET_SIS;
	case WRITE_ACKED_BY_PEER:
		/* Normal operation protocol C: successfully written on peer.
		 * During resync, even in protocol != C,
		 * we requested an explicit write ack anyways.
		 * Which means we cannot even assert anything here.
		 * Nothing more to do here.
		 * We want to keep the tl in place for all protocols, to cater
		 * for volatile write-back caches on lower level devices. */
		goto ack_common;
	case RECV_ACKED_BY_PEER:
		D_ASSERT(device, req->net_rq_state[idx] & RQ_EXP_RECEIVE_ACK);
		/* protocol B; pretends to be successfully written on peer.
		 * see also notes above in HANDED_OVER_TO_NETWORK about
		 * protocol != C */
	ack_common:
		mod_rq_state(req, m, peer_device, RQ_NET_PENDING, RQ_NET_OK);
		break;

	case POSTPONE_WRITE:
		D_ASSERT(device, req->net_rq_state[idx] & RQ_EXP_WRITE_ACK);
		/* If this node has already detected the write conflict, the
		 * worker will be waiting on misc_wait.  Wake it up once this
		 * request has completed locally.
		 */
		D_ASSERT(device, req->net_rq_state[idx] & RQ_NET_PENDING);
		req->local_rq_state |= RQ_POSTPONED;
		if (req->i.waiting)
			wake_up(&req->device->misc_wait);
		/* Do not clear RQ_NET_PENDING. This request will make further
		 * progress via restart_conflicting_writes() or
		 * fail_postponed_requests(). Hopefully. */
		break;

	case NEG_ACKED:
		mod_rq_state(req, m, peer_device, RQ_NET_OK|RQ_NET_PENDING,
			     (req->local_rq_state & RQ_WRITE) ? 0 : RQ_NET_DONE);
		break;

	case COMPLETION_RESUMED:
		mod_rq_state(req, m, peer_device, RQ_COMPLETION_SUSP, 0);
		break;

	case FAIL_FROZEN_DISK_IO:
		if (!(req->local_rq_state & RQ_LOCAL_COMPLETED))
			break;
		mod_rq_state(req, m, peer_device, RQ_COMPLETION_SUSP, 0);
		break;

	case RESEND:
		/* Simply complete (local only) READs. */
		if (!(req->local_rq_state & RQ_WRITE) && !(req->net_rq_state[idx] & RQ_NET_MASK)) {
			mod_rq_state(req, m, peer_device, RQ_COMPLETION_SUSP, 0);
			break;
		}

		/* If RQ_NET_OK is already set, we got a P_WRITE_ACK or P_RECV_ACK
		   before the connection loss (B&C only); only P_BARRIER_ACK
		   (or the local completion?) was missing when we suspended.
		   Throwing them out of the TL here by pretending we got a BARRIER_ACK.
		   During connection handshake, we ensure that the peer was not rebooted.

		   Resending is only allowed on synchronous connections,
		   where all requests not yet completed to upper layers would
		   be in the same "reorder-domain", there can not possibly be
		   any dependency between incomplete requests, and we are
		   allowed to complete this one "out-of-sequence".
		 */
		if (!(req->net_rq_state[idx] & RQ_NET_OK)) {
			mod_rq_state(req, m, peer_device, RQ_COMPLETION_SUSP,
					RQ_NET_QUEUED|RQ_NET_PENDING);
			break;
		}
		fallthrough;	/* to BARRIER_ACKED */
	case BARRIER_ACKED:
		/* barrier ack for READ requests does not make sense */
		if (!(req->local_rq_state & RQ_WRITE))
			break;

		if (req->net_rq_state[idx] & RQ_NET_PENDING) {
			/* barrier came in before all requests were acked.
			 * this is bad, because if the connection is lost now,
			 * we won't be able to clean them up... */
			drbd_err(device, "FIXME (BARRIER_ACKED but pending)\n");
			mod_rq_state(req, m, peer_device, RQ_NET_PENDING, RQ_NET_OK);
		}
		/* Allowed to complete requests, even while suspended.
		 * As this is called for all requests within a matching epoch,
		 * we need to filter, and only set RQ_NET_DONE for those that
		 * have actually been on the wire. */
		mod_rq_state(req, m, peer_device, RQ_COMPLETION_SUSP,
				(req->net_rq_state[idx] & RQ_NET_MASK) ? RQ_NET_DONE : 0);
		break;

	case DATA_RECEIVED:
		D_ASSERT(device, req->net_rq_state[idx] & RQ_NET_PENDING);
		mod_rq_state(req, m, peer_device, RQ_NET_PENDING, RQ_NET_OK|RQ_NET_DONE);
		break;

	case QUEUE_AS_DRBD_BARRIER:
		start_new_tl_epoch(device->resource);
		for_each_peer_device(peer_device, device)
			mod_rq_state(req, m, peer_device, 0, RQ_NET_OK|RQ_NET_DONE);
		break;
	};
}

/* we may do a local read if:
 * - we are consistent (of course),
 * - or we are generally inconsistent,
 *   BUT we are still/already IN SYNC with all peers for this area.
 *   since size may be bigger than BM_BLOCK_SIZE,
 *   we may need to check several bits.
 */
static bool drbd_may_do_local_read(struct drbd_device *device, sector_t sector, int size)
{
	struct drbd_md *md = &device->ldev->md;
	unsigned int node_id;
	unsigned int n_checked = 0;

	unsigned long sbnr, ebnr;
	sector_t esector, nr_sectors;

	if (device->disk_state[NOW] == D_UP_TO_DATE)
		return true;
	if (device->disk_state[NOW] != D_INCONSISTENT)
		return false;
	esector = sector + (size >> 9) - 1;
	nr_sectors = get_capacity(device->vdisk);
	D_ASSERT(device, sector  < nr_sectors);
	D_ASSERT(device, esector < nr_sectors);

	sbnr = BM_SECT_TO_BIT(sector);
	ebnr = BM_SECT_TO_BIT(esector);

	for (node_id = 0; node_id < DRBD_NODE_ID_MAX; node_id++) {
		struct drbd_peer_md *peer_md = &md->peers[node_id];

		/* Skip bitmap indexes which are not assigned to a peer. */
		if (!(peer_md->flags & MDF_HAVE_BITMAP))
			continue;

		if (drbd_bm_count_bits(device, peer_md->bitmap_index, sbnr, ebnr))
			return false;
		++n_checked;
	}
	if (n_checked == 0) {
		if (drbd_ratelimit()) {
			drbd_err(device, "No valid bitmap slots found to check!\n");
		}
		return false;
	}
	return true;
}

/* TODO improve for more than one peer.
 * also take into account the drbd protocol. */
static bool remote_due_to_read_balancing(struct drbd_device *device,
		struct drbd_peer_device *peer_device, sector_t sector,
		enum drbd_read_balancing rbm)
{
	struct backing_dev_info *bdi;
	int stripe_shift;

	switch (rbm) {
	case RB_CONGESTED_REMOTE:
		bdi = device->ldev->backing_bdev->bd_disk->queue->backing_dev_info;
		return bdi_read_congested(bdi);
	case RB_LEAST_PENDING:
		return atomic_read(&device->local_cnt) >
			atomic_read(&peer_device->ap_pending_cnt) + atomic_read(&peer_device->rs_pending_cnt);
	case RB_32K_STRIPING:  /* stripe_shift = 15 */
	case RB_64K_STRIPING:
	case RB_128K_STRIPING:
	case RB_256K_STRIPING:
	case RB_512K_STRIPING:
	case RB_1M_STRIPING:   /* stripe_shift = 20 */
		stripe_shift = (rbm - RB_32K_STRIPING + 15);
		return (sector >> (stripe_shift - 9)) & 1;
	case RB_ROUND_ROBIN:
		return test_and_change_bit(READ_BALANCE_RR, &device->flags);
	case RB_PREFER_REMOTE:
		return true;
	case RB_PREFER_LOCAL:
	default:
		return false;
	}
}

/*
 * complete_conflicting_writes  -  wait for any conflicting write requests
 *
 * The write_requests tree contains all active write requests which we
 * currently know about.  Wait for any requests to complete which conflict with
 * the new one.
 *
 * Only way out: remove the conflicting intervals from the tree.
 */
static void complete_conflicting_writes(struct drbd_request *req)
{
	DEFINE_WAIT(wait);
	struct drbd_device *device = req->device;
	struct drbd_interval *i;
	sector_t sector = req->i.sector;
	int size = req->i.size;

	for (;;) {
		drbd_for_each_overlap(i, &device->write_requests, sector, size) {
			/* Ignore, if already completed to upper layers. */
			if (i->completed)
				continue;
			/* Handle the first found overlap.  After the schedule
			 * we have to restart the tree walk. */
			break;
		}
		if (!i)	/* if any */
			break;

		/* Indicate to wake up device->misc_wait on progress.  */
		prepare_to_wait(&device->misc_wait, &wait, TASK_UNINTERRUPTIBLE);
		i->waiting = true;
		spin_unlock_irq(&device->resource->req_lock);
		schedule();
		spin_lock_irq(&device->resource->req_lock);
	}
	finish_wait(&device->misc_wait, &wait);
}

/* called within req_lock and rcu_read_lock() */
static void __maybe_pull_ahead(struct drbd_device *device, struct drbd_connection *connection)
{
	struct net_conf *nc;
	bool congested = false;
	enum drbd_on_congestion on_congestion;
	u32 cong_fill = 0, cong_extents = 0;
	struct drbd_peer_device *peer_device = conn_peer_device(connection, device->vnr);

	if (connection->agreed_pro_version < 96)
		return;

	rcu_read_lock();
	nc = rcu_dereference(connection->transport.net_conf);
	if (nc) {
		on_congestion = nc->on_congestion;
		cong_fill = nc->cong_fill;
		cong_extents = nc->cong_extents;
	} else {
		on_congestion = OC_BLOCK;
	}
	rcu_read_unlock();
	if (on_congestion == OC_BLOCK)
		return;

	if (on_congestion == OC_PULL_AHEAD && peer_device->repl_state[NOW] == L_AHEAD)
		return; /* nothing to do ... */

	/* If I don't even have good local storage, we can not reasonably try
	 * to pull ahead of the peer. We also need the local reference to make
	 * sure device->act_log is there.
	 */
	if (!get_ldev_if_state(device, D_UP_TO_DATE))
		return;

	/* if an other volume already found that we are congested, short circuit. */
	congested = test_bit(CONN_CONGESTED, &connection->flags);

	if (!congested && cong_fill) {
		int n = atomic_read(&connection->ap_in_flight) +
			atomic_read(&connection->rs_in_flight);
		if (n >= cong_fill) {
			drbd_info(device, "Congestion-fill threshold reached (%d >= %d)\n", n, cong_fill);
			congested = true;
		}
	}

	if (!congested && device->act_log->used >= cong_extents) {
		drbd_info(device, "Congestion-extents threshold reached (%d >= %d)\n",
			device->act_log->used, cong_extents);
		congested = true;
	}

	if (congested) {
		struct drbd_resource *resource = device->resource;

		set_bit(CONN_CONGESTED, &connection->flags);

		/* start a new epoch for non-mirrored writes */
		start_new_tl_epoch(resource);

		begin_state_change_locked(resource, CS_VERBOSE | CS_HARD);
		if (on_congestion == OC_PULL_AHEAD)
			__change_repl_state(peer_device, L_AHEAD);
		else			/* on_congestion == OC_DISCONNECT */
			__change_cstate(peer_device->connection, C_DISCONNECTING);
		end_state_change_locked(resource);
	}
	put_ldev(device);
}

/* called within req_lock */
static void maybe_pull_ahead(struct drbd_device *device)
{
	struct drbd_connection *connection;

	for_each_connection(connection, device->resource)
		if (connection->cstate[NOW] == C_CONNECTED)
			__maybe_pull_ahead(device, connection);
}

bool drbd_should_do_remote(struct drbd_peer_device *peer_device, enum which_state which)
{
	enum drbd_disk_state peer_disk_state = peer_device->disk_state[which];
	enum drbd_repl_state repl_state = peer_device->repl_state[which];

	return peer_disk_state == D_UP_TO_DATE ||
		(peer_disk_state == D_INCONSISTENT &&
		 (repl_state == L_ESTABLISHED ||
		  (repl_state >= L_WF_BITMAP_T && repl_state < L_AHEAD)));
	/* Before proto 96 that was >= CONNECTED instead of >= L_WF_BITMAP_T.
	   That is equivalent since before 96 IO was frozen in the L_WF_BITMAP*
	   states. */
}

static bool drbd_should_send_out_of_sync(struct drbd_peer_device *peer_device)
{
	return peer_device->repl_state[NOW] == L_AHEAD || peer_device->repl_state[NOW] == L_WF_BITMAP_S;
	/* pdsk = D_INCONSISTENT as a consequence. Protocol 96 check not necessary
	   since we enter state L_AHEAD only if proto >= 96 */
}

/* Prefer to read from protcol C peers, then B, last A */
static u64 calc_nodes_to_read_from(struct drbd_device *device)
{
	struct drbd_peer_device *peer_device;
	u64 candidates[DRBD_PROT_C] = {};
	int wp;

	rcu_read_lock();
	for_each_peer_device_rcu(peer_device, device) {
		struct net_conf *nc;

		if (peer_device->disk_state[NOW] != D_UP_TO_DATE)
			continue;
		nc = rcu_dereference(peer_device->connection->transport.net_conf);
		if (!nc || !nc->allow_remote_read)
			continue;
		wp = nc->wire_protocol;
		candidates[wp - 1] |= NODE_MASK(peer_device->node_id);
	}
	rcu_read_unlock();

	for (wp = DRBD_PROT_C; wp >= DRBD_PROT_A; wp--) {
		if (candidates[wp - 1])
			return candidates[wp - 1];
	}
	return 0;
}

/* If this returns NULL, and req->private_bio is still set,
 * the request should be submitted locally.
 *
 * If it returns NULL, but req->private_bio is not set,
 * we do not have access to good data :(
 *
 * Otherwise, this destroys req->private_bio, if any,
 * and returns the peer device which should be asked for data.
 */
static struct drbd_peer_device *find_peer_device_for_read(struct drbd_request *req)
{
	struct drbd_peer_device *peer_device;
	struct drbd_device *device = req->device;
	enum drbd_read_balancing rbm = RB_PREFER_REMOTE;

	if (req->private_bio) {
		if (!drbd_may_do_local_read(device,
					req->i.sector, req->i.size)) {
			bio_put(req->private_bio);
			req->private_bio = NULL;
			put_ldev(device);
		}
	}

	if (device->disk_state[NOW] > D_DISKLESS) {
		rcu_read_lock();
		rbm = rcu_dereference(device->ldev->disk_conf)->read_balancing;
		rcu_read_unlock();
		if (rbm == RB_PREFER_LOCAL && req->private_bio) {
			return NULL; /* submit locally */
		}
	}

	/* TODO: improve read balancing decisions, allow user to configure node weights */
	while (true) {
		if (!device->read_nodes)
			device->read_nodes = calc_nodes_to_read_from(device);
		if (device->read_nodes) {
			int peer_node_id = __ffs64(device->read_nodes);
			device->read_nodes &= ~NODE_MASK(peer_node_id);
			peer_device = peer_device_by_node_id(device, peer_node_id);
			if (!peer_device)
				continue;
			if (peer_device->disk_state[NOW] != D_UP_TO_DATE)
				continue;
			if (req->private_bio &&
			    !remote_due_to_read_balancing(device, peer_device, req->i.sector, rbm))
				peer_device = NULL;
		} else {
			peer_device = NULL;
		}
		break;
	}

	if (peer_device && req->private_bio) {
		bio_put(req->private_bio);
		req->private_bio = NULL;
		put_ldev(device);
	}
	return peer_device;
}

/* returns the number of connections expected to actually write this data,
 * which does NOT include those that we are L_AHEAD for. */
static int drbd_process_write_request(struct drbd_request *req)
{
	struct drbd_device *device = req->device;
	struct drbd_peer_device *peer_device;
	bool in_tree = false;
	int remote, send_oos;
	int count = 0;

	for_each_peer_device(peer_device, device) {
		remote = drbd_should_do_remote(peer_device, NOW);
		send_oos = drbd_should_send_out_of_sync(peer_device);

		if (!remote && !send_oos)
			continue;

		D_ASSERT(device, !(remote && send_oos));

		if (remote) {
			++count;
			_req_mod(req, TO_BE_SENT, peer_device);
			if (!in_tree) {
				/* Corresponding drbd_remove_request_interval is in
				 * drbd_req_complete() */
				drbd_insert_interval(&device->write_requests, &req->i);
				in_tree = true;
			}
			_req_mod(req, QUEUE_FOR_NET_WRITE, peer_device);
		} else
			_req_mod(req, QUEUE_FOR_SEND_OOS, peer_device);
	}

	return count;
}

static void drbd_process_discard_or_zeroes_req(struct drbd_request *req, int flags)
{
	int err = drbd_issue_discard_or_zero_out(req->device,
				req->i.sector, req->i.size >> 9, flags);
	req->private_bio->bi_status = err ? BLK_STS_IOERR : BLK_STS_OK;
	bio_endio(req->private_bio);
}

static void
drbd_submit_req_private_bio(struct drbd_request *req)
{
	struct drbd_device *device = req->device;
	struct bio *bio = req->private_bio;
	unsigned int type;

	if (bio_op(bio) != REQ_OP_READ)
		type = DRBD_FAULT_DT_WR;
	else if (bio->bi_opf & REQ_RAHEAD)
		type = DRBD_FAULT_DT_RA;
	else
		type = DRBD_FAULT_DT_RD;

	bio_set_dev(bio, device->ldev->backing_bdev);

	/* State may have changed since we grabbed our reference on the
	 * device->ldev member. Double check, and short-circuit to endio.
	 * In case the last activity log transaction failed to get on
	 * stable storage, and this is a WRITE, we may not even submit
	 * this bio. */
	if (get_ldev(device)) {
		if (drbd_insert_fault(device, type)) {
			bio->bi_status = BLK_STS_IOERR;
			bio_endio(bio);
		} else if (bio_op(bio) == REQ_OP_WRITE_ZEROES) {
			drbd_process_discard_or_zeroes_req(req, EE_ZEROOUT |
			    ((bio->bi_opf & REQ_NOUNMAP) ? 0 : EE_TRIM));
		} else if (bio_op(bio) == REQ_OP_DISCARD) {
			drbd_process_discard_or_zeroes_req(req, EE_TRIM);
		} else {
			submit_bio_noacct(bio);
		}
		put_ldev(device);
	} else {
		bio->bi_status = BLK_STS_IOERR;
		bio_endio(bio);
	}
 }

static void drbd_queue_write(struct drbd_device *device, struct drbd_request *req)
{
	if (req->private_bio)
		atomic_inc(&device->ap_actlog_cnt);
	spin_lock_irq(&device->resource->req_lock);
	list_add_tail(&req->tl_requests, &device->submit.writes);
	list_add_tail(&req->req_pending_master_completion,
			&device->pending_master_completion[1 /* WRITE */]);
	spin_unlock_irq(&device->resource->req_lock);
	queue_work(device->submit.wq, &device->submit.worker);
	/* do_submit() may sleep internally on al_wait, too */
	wake_up(&device->al_wait);
}

static void req_make_private_bio(struct drbd_request *req, struct bio *bio_src)
{
	struct bio *bio;
	bio = bio_clone_fast(bio_src, GFP_NOIO, &drbd_io_bio_set);

	req->private_bio = bio;

	bio->bi_private  = req;
	bio->bi_end_io   = drbd_request_endio;
	bio->bi_next     = NULL;
}

static void drbd_req_in_actlog(struct drbd_request *req)
{
	req->local_rq_state |= RQ_IN_ACT_LOG;
	ktime_get_accounting(req->in_actlog_kt);
	atomic_sub(interval_to_al_extents(&req->i), &req->device->wait_for_actlog_ecnt);
}

/* returns the new drbd_request pointer, if the caller is expected to
 * drbd_send_and_submit() it (to save latency), or NULL if we queued the
 * request on the submitter thread.
 * Returns ERR_PTR(-ENOMEM) if we cannot allocate a drbd_request.
 */
#ifndef CONFIG_DRBD_TIMING_STATS
#define drbd_request_prepare(d,b,k,j) drbd_request_prepare(d,b,j)
#endif
static struct drbd_request *
drbd_request_prepare(struct drbd_device *device, struct bio *bio,
		ktime_t start_kt,
		unsigned long start_jif)
{
	const int rw = bio_data_dir(bio);
	struct drbd_request *req;

	/* allocate outside of all locks; */
	req = drbd_req_new(device, bio);
	if (!req) {
		dec_ap_bio(device, rw);
		/* only pass the error to the upper layers.
		 * if user cannot handle io errors, that's not our business. */
		drbd_err(device, "could not kmalloc() req\n");
		bio->bi_status = BLK_STS_RESOURCE;
		bio_endio(bio);
		return ERR_PTR(-ENOMEM);
	}

	/* Update disk stats */
	req->start_jif = bio_start_io_acct(req->master_bio);

	if (get_ldev(device))
		req_make_private_bio(req, bio);

	ktime_get_accounting_assign(req->start_kt, start_kt);

	if (rw != WRITE || req->i.size == 0)
		return req;

	/* Let the activity log know we are about to use it...
	 * FIXME
	 * Needs to slow down to not congest on the activity log, in case we
	 * have multiple primaries and the peer sends huge scattered epochs.
	 * See also how peer_requests are handled
	 * in receive_Data() { ... prepare_activity_log(); ... }
	 */
	if (req->private_bio)
		atomic_add(interval_to_al_extents(&req->i), &device->wait_for_actlog_ecnt);

	/* process discards always from our submitter thread */
	if ((bio_op(bio) == REQ_OP_WRITE_ZEROES) ||
	    (bio_op(bio) == REQ_OP_DISCARD))
		goto queue_for_submitter_thread;

	if (req->private_bio && !test_bit(AL_SUSPENDED, &device->flags)) {
		if (!drbd_al_begin_io_fastpath(device, &req->i))
			goto queue_for_submitter_thread;
		drbd_req_in_actlog(req);
	}
	return req;

 queue_for_submitter_thread:
	ktime_aggregate_delta(device, req->start_kt, before_queue_kt);
	drbd_queue_write(device, req);
	return NULL;
}

/* Require at least one path to current data.
 * We don't want to allow writes on C_STANDALONE D_INCONSISTENT:
 * We would not allow to read what was written,
 * we would not have bumped the data generation uuids,
 * we would cause data divergence for all the wrong reasons.
 *
 * If we don't see at least one D_UP_TO_DATE, we will fail this request,
 * which either returns EIO, or, if OND_SUSPEND_IO is set, suspends IO,
 * and queues for retry later.
 */
static bool may_do_writes(struct drbd_device *device)
{
	struct drbd_peer_device *peer_device;

	if (device->disk_state[NOW] == D_UP_TO_DATE)
		return true;

	for_each_peer_device(peer_device, device) {
		if (peer_device->disk_state[NOW] == D_UP_TO_DATE)
		    return true;
	}

	return false;
}

struct drbd_plug_cb {
	struct blk_plug_cb cb;
	struct drbd_request *most_recent_req;
	/* do we need more? */
};

static void drbd_unplug(struct blk_plug_cb *cb, bool from_schedule)
{
	struct drbd_plug_cb *plug = container_of(cb, struct drbd_plug_cb, cb);
	struct drbd_resource *resource = plug->cb.data;
	struct drbd_request *req = plug->most_recent_req;

	kfree(cb);
	if (!req)
		return;

	spin_lock_irq(&resource->req_lock);
	/* In case the sender did not process it yet, raise the flag to
	 * have it followed with P_UNPLUG_REMOTE just after. */
	req->local_rq_state |= RQ_UNPLUG;
	/* but also queue a generic unplug */
	drbd_queue_unplug(req->device);
	kref_put(&req->kref, drbd_req_destroy);
	spin_unlock_irq(&resource->req_lock);
}

static struct drbd_plug_cb* drbd_check_plugged(struct drbd_resource *resource)
{
	/* A lot of text to say
	 * return (struct drbd_plug_cb*)blk_check_plugged(); */
	struct drbd_plug_cb *plug;
	struct blk_plug_cb *cb = blk_check_plugged(drbd_unplug, resource, sizeof(*plug));

	if (cb)
		plug = container_of(cb, struct drbd_plug_cb, cb);
	else
		plug = NULL;
	return plug;
}

static void drbd_update_plug(struct drbd_plug_cb *plug, struct drbd_request *req)
{
	struct drbd_request *tmp = plug->most_recent_req;
	/* Will be sent to some peer.
	 * Remember to tag it with UNPLUG_REMOTE on unplug */
	kref_get(&req->kref);
	plug->most_recent_req = req;
	if (tmp)
		kref_put(&tmp->kref, drbd_req_destroy);
}

static void drbd_send_and_submit(struct drbd_device *device, struct drbd_request *req)
{
	struct drbd_resource *resource = device->resource;
	struct drbd_peer_device *peer_device = NULL; /* for read */
	const int rw = bio_data_dir(req->master_bio);
	struct bio_and_error m = { NULL, };
	bool no_remote = false;
	bool submit_private_bio = false;

	spin_lock_irq(&resource->req_lock);
	if (rw == WRITE) {
		/* This may temporarily give up the req_lock,
		 * but will re-acquire it before it returns here.
		 * Needs to be before the check on drbd_suspended() */
		complete_conflicting_writes(req);
		/* no more giving up req_lock from now on! */

		/* check for congestion, and potentially stop sending
		 * full data updates, but start sending "dirty bits" only. */
		maybe_pull_ahead(device);
	}


	if (drbd_suspended(device)) {
		/* push back and retry: */
		req->local_rq_state |= RQ_POSTPONED;
		if (req->private_bio) {
			bio_put(req->private_bio);
			req->private_bio = NULL;
			put_ldev(device);
		}
		goto out;
	}

	/* We fail READ early, if we can not serve it.
	 * We must do this before req is registered on any lists.
	 * Otherwise, drbd_req_complete() will queue failed READ for retry. */
	if (rw != WRITE) {
		peer_device = find_peer_device_for_read(req);
		if (!peer_device && !req->private_bio)
			goto nodata;
	}

	/* which transfer log epoch does this belong to? */
	req->epoch = atomic_read(&resource->current_tle_nr);

	if (rw == WRITE)
		resource->dagtag_sector += req->i.size >> 9;
	req->dagtag_sector = resource->dagtag_sector;
	/* no point in adding empty flushes to the transfer log,
	 * they are mapped to drbd barriers already. */
	if (likely(req->i.size != 0)) {
		if (rw == WRITE) {
			struct drbd_request *req2;

			resource->current_tle_writes++;
			list_for_each_entry_reverse(req2, &resource->transfer_log, tl_requests) {
				if (req2->local_rq_state & RQ_WRITE) {
					/* Make the new write request depend on
					 * the previous one. */
					BUG_ON(req2->destroy_next);
					req2->destroy_next = req;
					kref_get(&req->kref);
					break;
				}
			}
		}
		list_add_tail(&req->tl_requests, &resource->transfer_log);
	}

	if (rw == WRITE) {
		if (req->private_bio && !may_do_writes(device)) {
			bio_put(req->private_bio);
			req->private_bio = NULL;
			put_ldev(device);
			goto nodata;
		}
		/* Need to replicate writes.  Unless it is an empty flush,
		 * which is better mapped to a DRBD P_BARRIER packet,
		 * also for drbd wire protocol compatibility reasons.
		 * If this was a flush, just start a new epoch.
		 * Unless the current epoch was empty anyways, or we are not currently
		 * replicating, in which case there is no point. */
		if (unlikely(req->i.size == 0)) {
			/* The only size==0 bios we expect are empty flushes. */
			D_ASSERT(device, req->master_bio->bi_opf & REQ_PREFLUSH);
			_req_mod(req, QUEUE_AS_DRBD_BARRIER, NULL);
		} else if (!drbd_process_write_request(req))
			no_remote = true;
		wake_all_senders(resource);
	} else {
		if (peer_device) {
			_req_mod(req, TO_BE_SENT, peer_device);
			_req_mod(req, QUEUE_FOR_NET_READ, peer_device);
			wake_up(&peer_device->connection->sender_work.q_wait);
		} else
			no_remote = true;
	}

	if (no_remote == false) {
		struct drbd_plug_cb *plug = drbd_check_plugged(resource);
		if (plug)
			drbd_update_plug(plug, req);
	}

	/* If it took the fast path in drbd_request_prepare, add it here.
	 * The slow path has added it already. */
	if (list_empty(&req->req_pending_master_completion))
		list_add_tail(&req->req_pending_master_completion,
			&device->pending_master_completion[rw == WRITE]);
	if (req->private_bio) {
		/* pre_submit_jif is used in request_timer_fn() */
		req->pre_submit_jif = jiffies;
		ktime_get_accounting(req->pre_submit_kt);
		list_add_tail(&req->req_pending_local,
			&device->pending_completion[rw == WRITE]);
		_req_mod(req, TO_BE_SUBMITTED, NULL);
		/* needs to be marked within the same spinlock
		 * but we need to give up the spinlock to submit */
		submit_private_bio = true;
	} else if (no_remote) {
nodata:
		if (drbd_ratelimit())
			drbd_err(req->device, "IO ERROR: neither local nor remote data, sector %llu+%u\n",
					(unsigned long long)req->i.sector, req->i.size >> 9);
		/* A write may have been queued for send_oos, however.
		 * So we can not simply free it, we must go through drbd_req_put_completion_ref() */
	}

out:
	drbd_req_put_completion_ref(req, &m, 1);
	spin_unlock_irq(&resource->req_lock);

	/* Even though above is a kref_put(), this is safe.
	 * As long as we still need to submit our private bio,
	 * we hold a completion ref, and the request cannot disappear.
	 * If however this request did not even have a private bio to submit
	 * (e.g. remote read), req may already be invalid now.
	 * That's why we cannot check on req->private_bio. */
	if (submit_private_bio)
		drbd_submit_req_private_bio(req);

	if (m.bio)
		complete_master_bio(device, &m);
}

static bool inc_ap_bio_cond(struct drbd_device *device, int rw)
{
	bool rv = false;
	unsigned int nr_requests;

	if (test_bit(NEW_CUR_UUID, &device->flags)) {
		if (!test_and_set_bit(WRITING_NEW_CUR_UUID, &device->flags))
			drbd_device_post_work(device, MAKE_NEW_CUR_UUID);

		return false;
	}

	spin_lock_irq(&device->resource->req_lock);
	nr_requests = device->resource->res_opts.nr_requests;
	rv = may_inc_ap_bio(device) && atomic_read(&device->ap_bio_cnt[rw]) < nr_requests;
	if (rv)
		atomic_inc(&device->ap_bio_cnt[rw]);
	spin_unlock_irq(&device->resource->req_lock);

	return rv;
}

static void inc_ap_bio(struct drbd_device *device, int rw)
{
	/* we wait here
	 *    as long as the device is suspended
	 *    until the bitmap is no longer on the fly during connection
	 *    handshake as long as we would exceed the max_buffer limit.
	 *
	 * to avoid races with the reconnect code,
	 * we need to atomic_inc within the spinlock. */

	wait_event(device->misc_wait, inc_ap_bio_cond(device, rw));
}

void __drbd_make_request(struct drbd_device *device, struct bio *bio,
		ktime_t start_kt,
		unsigned long start_jif)
{
	struct drbd_request *req;

	inc_ap_bio(device, bio_data_dir(bio));
	req = drbd_request_prepare(device, bio, start_kt, start_jif);
	if (IS_ERR_OR_NULL(req))
		return;
	drbd_send_and_submit(device, req);
}

/* helpers for do_submit */

struct incoming_pending_later {
	/* from drbd_submit_bio() or receive_Data() */
	struct list_head incoming;
	/* for non-blocking fill-up # of updates in the transaction */
	struct list_head more_incoming;
	/* to be submitted after next AL-transaction commit */
	struct list_head pending;
	/* currently blocked e.g. by concurrent resync requests */
	struct list_head later;
	/* need cleanup */
	struct list_head cleanup;
};

struct waiting_for_act_log {
	struct incoming_pending_later requests;
	struct incoming_pending_later peer_requests;
};

static void ipb_init(struct incoming_pending_later *ipb)
{
	INIT_LIST_HEAD(&ipb->incoming);
	INIT_LIST_HEAD(&ipb->more_incoming);
	INIT_LIST_HEAD(&ipb->pending);
	INIT_LIST_HEAD(&ipb->later);
	INIT_LIST_HEAD(&ipb->cleanup);
}

static void wfa_init(struct waiting_for_act_log *wfa)
{
	ipb_init(&wfa->requests);
	ipb_init(&wfa->peer_requests);
}

#define wfa_lists_empty(_wfa, name)	\
	(list_empty(&(_wfa)->requests.name) && list_empty(&(_wfa)->peer_requests.name))
#define wfa_splice_init(_wfa, from, to) do { \
	list_splice_init(&(_wfa)->requests.from, &(_wfa)->requests.to); \
	list_splice_init(&(_wfa)->peer_requests.from, &(_wfa)->peer_requests.to); \
	} while (0)
#define wfa_splice_tail_init(_wfa, from, to) do { \
	list_splice_tail_init(&(_wfa)->requests.from, &(_wfa)->requests.to); \
	list_splice_tail_init(&(_wfa)->peer_requests.from, &(_wfa)->peer_requests.to); \
	} while (0)

static void __drbd_submit_peer_request(struct drbd_peer_request *peer_req)
{
	struct drbd_peer_device *peer_device = peer_req->peer_device;
	struct drbd_device *device = peer_device->device;
	int err;

	peer_req->flags |= EE_IN_ACTLOG;
	atomic_sub(interval_to_al_extents(&peer_req->i), &device->wait_for_actlog_ecnt);
	atomic_dec(&device->wait_for_actlog);
	list_del_init(&peer_req->wait_for_actlog);

	err = drbd_submit_peer_request(peer_req);

	if (err)
		drbd_cleanup_after_failed_submit_peer_request(peer_req);
}

static void submit_fast_path(struct drbd_device *device, struct waiting_for_act_log *wfa)
{
	struct blk_plug plug;
	struct drbd_request *req, *tmp;
	struct drbd_peer_request *pr, *pr_tmp;

	blk_start_plug(&plug);
	list_for_each_entry_safe(pr, pr_tmp, &wfa->peer_requests.incoming, wait_for_actlog) {
		if (!drbd_al_begin_io_fastpath(pr->peer_device->device, &pr->i))
			continue;

		__drbd_submit_peer_request(pr);
	}
	list_for_each_entry_safe(req, tmp, &wfa->requests.incoming, tl_requests) {
		const int rw = bio_data_dir(req->master_bio);

		if (rw == WRITE && req->private_bio && req->i.size
		&& !test_bit(AL_SUSPENDED, &device->flags)) {
			if (!drbd_al_begin_io_fastpath(device, &req->i))
				continue;

			drbd_req_in_actlog(req);
			atomic_dec(&device->ap_actlog_cnt);
		}

		list_del_init(&req->tl_requests);
		drbd_send_and_submit(device, req);
	}
	blk_finish_plug(&plug);
}

static struct drbd_request *wfa_next_request(struct waiting_for_act_log *wfa)
{
	struct list_head *lh = !list_empty(&wfa->requests.more_incoming) ?
			&wfa->requests.more_incoming: &wfa->requests.incoming;
	return list_first_entry_or_null(lh, struct drbd_request, tl_requests);
}

static struct drbd_peer_request *wfa_next_peer_request(struct waiting_for_act_log *wfa)
{
	struct list_head *lh = !list_empty(&wfa->peer_requests.more_incoming) ?
			&wfa->peer_requests.more_incoming: &wfa->peer_requests.incoming;
	return list_first_entry_or_null(lh, struct drbd_peer_request, wait_for_actlog);
}

static bool prepare_al_transaction_nonblock(struct drbd_device *device,
					    struct waiting_for_act_log *wfa)
{
	struct drbd_peer_request *peer_req;
	struct drbd_request *req;
	bool made_progress = false;
	bool wake = false;
	int err;

	spin_lock_irq(&device->al_lock);

	/* Don't even try, if someone has it locked right now. */
	if (test_bit(__LC_LOCKED, &device->act_log->flags))
		goto out;

	while ((peer_req = wfa_next_peer_request(wfa))) {
		if (peer_req->peer_device->connection->cstate[NOW] < C_CONNECTED) {
			list_move_tail(&peer_req->wait_for_actlog, &wfa->peer_requests.cleanup);
			made_progress = true;
			continue;
		}
		err = drbd_al_begin_io_nonblock(device, &peer_req->i);
		if (err == -ENOBUFS)
			break;
		if (err == -EBUSY)
			wake = true;
		if (err)
			list_move_tail(&peer_req->wait_for_actlog, &wfa->peer_requests.later);
		else {
			list_move_tail(&peer_req->wait_for_actlog, &wfa->peer_requests.pending);
			made_progress = true;
		}
	}
	while ((req = wfa_next_request(wfa))) {
		ktime_aggregate_delta(device, req->start_kt, before_al_begin_io_kt);
		err = drbd_al_begin_io_nonblock(device, &req->i);
		if (err == -ENOBUFS)
			break;
		if (err == -EBUSY)
			wake = true;
		if (err)
			list_move_tail(&req->tl_requests, &wfa->requests.later);
		else {
			list_move_tail(&req->tl_requests, &wfa->requests.pending);
			made_progress = true;
		}
	}
 out:
	spin_unlock_irq(&device->al_lock);
	if (wake)
		wake_up(&device->al_wait);
	return made_progress;
}

static void send_and_submit_pending(struct drbd_device *device, struct waiting_for_act_log *wfa)
{
	struct blk_plug plug;
	struct drbd_request *req, *tmp;
	struct drbd_peer_request *pr, *pr_tmp;

	blk_start_plug(&plug);
	list_for_each_entry_safe(pr, pr_tmp, &wfa->peer_requests.pending, wait_for_actlog) {
		__drbd_submit_peer_request(pr);
	}
	list_for_each_entry_safe(req, tmp, &wfa->requests.pending, tl_requests) {
		drbd_req_in_actlog(req);
		atomic_dec(&device->ap_actlog_cnt);
		list_del_init(&req->tl_requests);
		drbd_send_and_submit(device, req);
	}
	blk_finish_plug(&plug);
}

/* more: for non-blocking fill-up # of updates in the transaction */
static bool grab_new_incoming_requests(struct drbd_device *device, struct waiting_for_act_log *wfa, bool more)
{
	/* grab new incoming requests */
	struct list_head *reqs = more ? &wfa->requests.more_incoming : &wfa->requests.incoming;
	struct list_head *peer_reqs = more ? &wfa->peer_requests.more_incoming : &wfa->peer_requests.incoming;
	bool found_new = false;

	spin_lock_irq(&device->resource->req_lock);
	found_new = !list_empty(&device->submit.writes);
	list_splice_tail_init(&device->submit.writes, reqs);
	found_new |= !list_empty(&device->submit.peer_writes);
	list_splice_tail_init(&device->submit.peer_writes, peer_reqs);
	spin_unlock_irq(&device->resource->req_lock);

	return found_new;
}

void do_submit(struct work_struct *ws)
{
	struct drbd_device *device = container_of(ws, struct drbd_device, submit.worker);
	struct waiting_for_act_log wfa;
	bool made_progress;

	wfa_init(&wfa);

	grab_new_incoming_requests(device, &wfa, false);

	for (;;) {
		DEFINE_WAIT(wait);

		/* move used-to-be-postponed back to front of incoming */
		wfa_splice_init(&wfa, later, incoming);
		submit_fast_path(device, &wfa);
		if (wfa_lists_empty(&wfa, incoming))
			break;

		for (;;) {
			/*
			 * We put ourselves on device->al_wait, then check if
			 * we can need to actually sleep and wait for someone
			 * else to make progress.
			 *
			 * We need to sleep if we cannot activate enough
			 * activity log extents for even one single request.
			 * That would mean that all (peer-)requests in our incoming lists
			 * either target "cold" activity log extent, all
			 * activity log extent slots are have on-going
			 * in-flight IO (are "hot"), and no idle or free slot
			 * is available, or the target regions are busy doing resync,
			 * and lock out application requests for that reason.
			 *
			 * prepare_to_wait() can internally cause a wake_up()
			 * as well, though, so this may appear to busy-loop
			 * a couple times, but should settle down quickly.
			 *
			 * When resync and/or application requests make
			 * sufficient progress, some refcount on some extent
			 * will eventually drop to zero, we will be woken up,
			 * and can try to move that now idle extent to "cold",
			 * and recycle it's slot for one of the extents we'd
			 * like to become hot.
			 */
			prepare_to_wait(&device->al_wait, &wait, TASK_UNINTERRUPTIBLE);

			wfa_splice_init(&wfa, later, incoming);
			made_progress = prepare_al_transaction_nonblock(device, &wfa);
			if (made_progress)
				break;

			schedule();

			/* If all currently "hot" activity log extents are kept busy by
			 * incoming requests, we still must not totally starve new
			 * requests to "cold" extents.
			 * Something left on &incoming means there had not been
			 * enough update slots available, and the activity log
			 * has been marked as "starving".
			 *
			 * Try again now, without looking for new requests,
			 * effectively blocking all new requests until we made
			 * at least _some_ progress with what we currently have.
			 */
			if (!wfa_lists_empty(&wfa, incoming))
				continue;

			/* Nothing moved to pending, but nothing left
			 * on incoming: all moved to "later"!
			 * Grab new and iterate. */
			grab_new_incoming_requests(device, &wfa, false);
		}
		finish_wait(&device->al_wait, &wait);

		/* If the transaction was full, before all incoming requests
		 * had been processed, skip ahead to commit, and iterate
		 * without splicing in more incoming requests from upper layers.
		 *
		 * Else, if all incoming have been processed,
		 * they have become either "pending" (to be submitted after
		 * next transaction commit) or "busy" (blocked by resync).
		 *
		 * Maybe more was queued, while we prepared the transaction?
		 * Try to stuff those into this transaction as well.
		 * Be strictly non-blocking here,
		 * we already have something to commit.
		 *
		 * Commit as soon as we don't make any more progress.
		 */

		while (wfa_lists_empty(&wfa, incoming)) {
			/* It is ok to look outside the lock,
			 * it's only an optimization anyways */
			if (list_empty(&device->submit.writes) &&
			    list_empty(&device->submit.peer_writes))
				break;

			if (!grab_new_incoming_requests(device, &wfa, true))
				break;

			made_progress = prepare_al_transaction_nonblock(device, &wfa);

			wfa_splice_tail_init(&wfa, more_incoming, incoming);
			if (!made_progress)
				break;
		}
		if (!list_empty(&wfa.peer_requests.cleanup))
			drbd_cleanup_peer_requests_wfa(device, &wfa.peer_requests.cleanup);

		drbd_al_begin_io_commit(device);

		send_and_submit_pending(device, &wfa);
	}
}

static bool drbd_fail_request_early(struct drbd_device *device, struct bio *bio)
{
	struct drbd_resource *resource = device->resource;

	/* If you "mount -o ro", then later "mount -o remount,rw", you can end
	 * up with a DRBD "Secondary" receiving WRITE requests from the VFS.
	 * We cannot have that. */
	if (resource->role[NOW] != R_PRIMARY && bio_data_dir(bio) == WRITE) {
		if (drbd_ratelimit())
		       drbd_err(device, "Rejected WRITE request, not in Primary role.\n");
		return true;
	}
	return false;
}

blk_qc_t drbd_submit_bio(struct bio *bio)
{
	struct request_queue *q = bio->bi_disk->queue;
	struct drbd_device *device = (struct drbd_device *) q->queuedata;
#ifdef CONFIG_DRBD_TIMING_STATS
	ktime_t start_kt;
#endif
	unsigned long start_jif;

	if (drbd_fail_request_early(device, bio)) {
		bio->bi_status = BLK_STS_IOERR;
		bio_endio(bio);
		return BLK_QC_T_NONE;
	}

	blk_queue_split(&bio);

	if (device->cached_err_io) {
		bio->bi_status = BLK_STS_IOERR;
		bio_endio(bio);
		return BLK_QC_T_NONE;
	}

	/* This is both an optimization: READ of size 0, nothing to do
	 * and a workaround: (older) ZFS explodes on size zero reads, see
	 * https://github.com/zfsonlinux/zfs/issues/8379
	 * Actually don't do anything for size zero bios.
	 * Add a "WARN_ONCE", so we can tell the caller to stop doing this.
	 */
	if (bio_op(bio) == REQ_OP_READ && bio->bi_iter.bi_size == 0) {
		WARN_ONCE(1, "size zero read from upper layers");
		bio->bi_status = BLK_STS_OK;
		bio_endio(bio);
		return BLK_QC_T_NONE;
	}

	ktime_get_accounting(start_kt);
	start_jif = jiffies;

	__drbd_make_request(device, bio, start_kt, start_jif);

	return BLK_QC_T_NONE;
}

static unsigned long time_min_in_future(unsigned long now,
		unsigned long t1, unsigned long t2)
{
	t1 = time_after(now, t1) ? now : t1;
	t2 = time_after(now, t2) ? now : t2;
	return time_after(t1, t2) ? t2 : t1;
}

static bool net_timeout_reached(struct drbd_request *net_req,
		struct drbd_connection *connection,
		unsigned long now, unsigned long ent,
		unsigned int ko_count, unsigned int timeout)
{
	struct drbd_device *device = net_req->device;
	struct drbd_peer_device *peer_device = conn_peer_device(connection, device->vnr);
	int peer_node_id = peer_device->node_id;
	unsigned long pre_send_jif = net_req->pre_send_jif[peer_node_id];

	if (!time_after(now, pre_send_jif + ent))
		return false;

	if (time_in_range(now, connection->last_reconnect_jif, connection->last_reconnect_jif + ent))
		return false;

	if (net_req->net_rq_state[peer_node_id] & RQ_NET_PENDING) {
		drbd_warn(device, "Remote failed to finish a request within %ums > ko-count (%u) * timeout (%u * 0.1s)\n",
			jiffies_to_msecs(now - pre_send_jif), ko_count, timeout);
		return true;
	}

	/* We received an ACK already (or are using protocol A),
	 * but are waiting for the epoch closing barrier ack.
	 * Check if we sent the barrier already.  We should not blame the peer
	 * for being unresponsive, if we did not even ask it yet. */
	if (net_req->epoch == connection->send.current_epoch_nr) {
		drbd_warn(device,
			"We did not send a P_BARRIER for %ums > ko-count (%u) * timeout (%u * 0.1s); drbd kernel thread blocked?\n",
			jiffies_to_msecs(now - pre_send_jif), ko_count, timeout);
		return false;
	}

	/* Worst case: we may have been blocked for whatever reason, then
	 * suddenly are able to send a lot of requests (and epoch separating
	 * barriers) in quick succession.
	 * The timestamp of the net_req may be much too old and not correspond
	 * to the sending time of the relevant unack'ed barrier packet, so
	 * would trigger a spurious timeout.  The latest barrier packet may
	 * have a too recent timestamp to trigger the timeout, potentially miss
	 * a timeout.  Right now we don't have a place to conveniently store
	 * these timestamps.
	 * But in this particular situation, the application requests are still
	 * completed to upper layers, DRBD should still "feel" responsive.
	 * No need yet to kill this connection, it may still recover.
	 * If not, eventually we will have queued enough into the network for
	 * us to block. From that point of view, the timestamp of the last sent
	 * barrier packet is relevant enough.
	 */
	if (time_after(now, connection->send.last_sent_barrier_jif + ent)) {
		drbd_warn(device, "Remote failed to answer a P_BARRIER (sent at %lu jif; now=%lu jif) within %ums > ko-count (%u) * timeout (%u * 0.1s)\n",
			connection->send.last_sent_barrier_jif, now,
			jiffies_to_msecs(now - connection->send.last_sent_barrier_jif), ko_count, timeout);
		return true;
	}
	return false;
}

/* A request is considered timed out, if
 * - we have some effective timeout from the configuration,
 *   with some state restrictions applied,
 * - the oldest request is waiting for a response from the network
 *   resp. the local disk,
 * - the oldest request is in fact older than the effective timeout,
 * - the connection was established (resp. disk was attached)
 *   for longer than the timeout already.
 * Note that for 32bit jiffies and very stable connections/disks,
 * we may have a wrap around, which is caught by
 *   !time_in_range(now, last_..._jif, last_..._jif + timeout).
 *
 * Side effect: once per 32bit wrap-around interval, which means every
 * ~198 days with 250 HZ, we have a window where the timeout would need
 * to expire twice (worst case) to become effective. Good enough.
 */

void request_timer_fn(struct timer_list *t)
{
	struct drbd_device *device = from_timer(device, t, request_timer);
	struct drbd_connection *connection;
	struct drbd_request *req_read, *req_write;
	unsigned long oldest_submit_jif;
	unsigned long dt = 0;
	unsigned long et = 0;
	unsigned long now = jiffies;
	unsigned long next_trigger_time = now;
	bool restart_timer = false;

	rcu_read_lock();
	if (get_ldev(device)) { /* implicit state.disk >= D_INCONSISTENT */
		dt = rcu_dereference(device->ldev->disk_conf)->disk_timeout * HZ / 10;
		put_ldev(device);
	}
	rcu_read_unlock();

	spin_lock_irq(&device->resource->req_lock);
	if (dt) {
		unsigned long write_pre_submit_jif = now, read_pre_submit_jif = now;
		req_read = list_first_entry_or_null(&device->pending_completion[0], struct drbd_request, req_pending_local);
		req_write = list_first_entry_or_null(&device->pending_completion[1], struct drbd_request, req_pending_local);

		if (req_write)
			write_pre_submit_jif = req_write->pre_submit_jif;
		if (req_read)
			read_pre_submit_jif = req_read->pre_submit_jif;
		oldest_submit_jif =
			(req_write && req_read)
			? ( time_before(write_pre_submit_jif, read_pre_submit_jif)
			  ? write_pre_submit_jif : read_pre_submit_jif )
			: req_write ? write_pre_submit_jif
			: req_read ? read_pre_submit_jif : now;

		if (device->disk_state[NOW] > D_FAILED) {
			et = min_not_zero(et, dt);
			next_trigger_time = time_min_in_future(now,
					next_trigger_time, oldest_submit_jif + dt);
			restart_timer = true;
		}

		if (time_after(now, oldest_submit_jif + dt) &&
		    !time_in_range(now, device->last_reattach_jif, device->last_reattach_jif + dt)) {
			drbd_warn(device, "Local backing device failed to meet the disk-timeout\n");
			__drbd_chk_io_error(device, DRBD_FORCE_DETACH);
		}
	}
	for_each_connection(connection, device->resource) {
		struct net_conf *nc;
		struct drbd_request *req;
		unsigned long ent = 0;
		unsigned long pre_send_jif = 0;
		unsigned int ko_count = 0, timeout = 0;

		/* maybe the oldest request waiting for the peer is in fact still
		 * blocking in tcp sendmsg.  That's ok, though, that's handled via the
		 * socket send timeout, requesting a ping, and bumping ko-count in
		 * we_should_drop_the_connection().
		 */

		/* check the oldest request we did successfully sent,
		 * but which is still waiting for an ACK. */
		req = connection->req_ack_pending;

		/* if we don't have such request (e.g. protocol A)
		 * check the oldest requests which is still waiting on its epoch
		 * closing barrier ack. */
		if (!req)
			req = connection->req_not_net_done;

		/* evaluate the oldest peer request only in one timer! */
		if (req && req->device != device)
			req = NULL;
		if (!req)
			continue;

		rcu_read_lock();
		nc = rcu_dereference(connection->transport.net_conf);
		if (nc) {
			/* effective timeout = ko_count * timeout */
			if (connection->cstate[NOW] == C_CONNECTED) {
				ko_count = nc->ko_count;
				timeout = nc->timeout;
			}
		}
		rcu_read_unlock();

		if (!timeout)
			continue;

		pre_send_jif = req->pre_send_jif[connection->peer_node_id];

		ent = timeout * HZ/10 * ko_count;
		et = min_not_zero(et, ent);
		next_trigger_time = time_min_in_future(now,
				next_trigger_time, pre_send_jif + ent);
		restart_timer = true;

		if (net_timeout_reached(req, connection, now, ent, ko_count, timeout)) {
			begin_state_change_locked(device->resource, CS_VERBOSE | CS_HARD);
			__change_cstate(connection, C_TIMEOUT);
			end_state_change_locked(device->resource);
		}
	}
	spin_unlock_irq(&device->resource->req_lock);

	if (restart_timer) {
		next_trigger_time = time_min_in_future(now, next_trigger_time, now + et);
		mod_timer(&device->request_timer, next_trigger_time);
	}
}
