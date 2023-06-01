// SPDX-License-Identifier: GPL-2.0-only
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
	req->i.type = bio_data_dir(bio_src) == WRITE ? INTERVAL_LOCAL_WRITE : INTERVAL_LOCAL_READ;

	INIT_LIST_HEAD(&req->tl_requests);
	INIT_LIST_HEAD(&req->list);
	INIT_LIST_HEAD(&req->req_pending_master_completion);
	INIT_LIST_HEAD(&req->req_pending_local);

	/* one reference to be put by __drbd_make_request */
	atomic_set(&req->completion_ref, 1);
	/* one kref as long as completion_ref > 0 */
	kref_init(&req->kref);
	spin_lock_init(&req->rq_lock);

	req->local_rq_state = (bio_data_dir(bio_src) == WRITE ? RQ_WRITE : 0)
	              | (bio_op(bio_src) == REQ_OP_WRITE_ZEROES ? RQ_ZEROES : 0)
	              | (bio_op(bio_src) == REQ_OP_DISCARD ? RQ_UNMAP : 0);

	return req;
}

void drbd_reclaim_req(struct rcu_head *rp)
{
	struct drbd_request *req = container_of(rp, struct drbd_request, rcu);
	mempool_free(req, &drbd_request_mempool);
}

static u64 peer_ack_mask(struct drbd_request *req)
{
	struct drbd_resource *resource = req->device->resource;
	struct drbd_connection *connection;
	u64 mask = 0;

	spin_lock_irq(&req->rq_lock);
	if (req->local_rq_state & RQ_LOCAL_OK)
		mask |= NODE_MASK(resource->res_opts.node_id);

	rcu_read_lock();
	for_each_connection_rcu(connection, resource) {
		int node_id = connection->peer_node_id;

		if (req->net_rq_state[node_id] & RQ_NET_OK)
			mask |= NODE_MASK(node_id);
	}
	rcu_read_unlock();
	spin_unlock_irq(&req->rq_lock);

	return mask;
}

static void queue_peer_ack_send(struct drbd_resource *resource,
		struct drbd_request *req, struct drbd_peer_ack *peer_ack)
{
	struct drbd_connection *connection;

	rcu_read_lock();
	for_each_connection_rcu(connection, resource) {
		unsigned int node_id = connection->peer_node_id;
		if (connection->agreed_pro_version < 110 ||
				connection->cstate[NOW] != C_CONNECTED ||
				!(req->net_rq_state[node_id] & RQ_NET_SENT))
			continue;

		peer_ack->pending_mask |= NODE_MASK(node_id);
		queue_work(connection->ack_sender, &connection->peer_ack_work);
	}
	rcu_read_unlock();
}

void drbd_destroy_peer_ack_if_done(struct drbd_peer_ack *peer_ack)
{
	struct drbd_resource *resource = peer_ack->resource;

	lockdep_assert_held(&resource->peer_ack_lock);

	if (peer_ack->pending_mask)
		return;

	list_del(&peer_ack->list);
	kfree(peer_ack);
}

int w_queue_peer_ack(struct drbd_work *w, int cancel)
{
	struct drbd_resource *resource =
		container_of(w, struct drbd_resource, peer_ack_work);
	LIST_HEAD(work_list);
	struct drbd_request *req, *tmp;

	spin_lock_irq(&resource->peer_ack_lock);
	list_splice_init(&resource->peer_ack_req_list, &work_list);
	spin_unlock_irq(&resource->peer_ack_lock);

	list_for_each_entry_safe(req, tmp, &work_list, list) {
		struct drbd_peer_ack *peer_ack =
			kzalloc(sizeof(struct drbd_peer_ack), GFP_KERNEL);

		peer_ack->resource = resource;
		INIT_LIST_HEAD(&peer_ack->list);
		peer_ack->mask = peer_ack_mask(req);
		peer_ack->dagtag_sector = req->dagtag_sector;

		spin_lock_irq(&resource->peer_ack_lock);
		list_add_tail(&peer_ack->list, &resource->peer_ack_list);
		queue_peer_ack_send(resource, req, peer_ack);
		drbd_destroy_peer_ack_if_done(peer_ack);
		spin_unlock_irq(&resource->peer_ack_lock);

		call_rcu(&req->rcu, drbd_reclaim_req);
	}
	return 0;
}

void drbd_queue_peer_ack(struct drbd_resource *resource, struct drbd_request *req)
{
	lockdep_assert_held(&resource->peer_ack_lock);

	list_add_tail(&req->list, &resource->peer_ack_req_list);
	drbd_queue_work_if_unqueued(&resource->work, &resource->peer_ack_work);
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

	lockdep_assert_irqs_disabled();

	spin_lock(&device->interval_lock);
	drbd_remove_interval(root, &req->i);
	spin_unlock(&device->interval_lock);
}

void drbd_req_destroy(struct kref *kref)
{
	struct drbd_request *req = container_of(kref, struct drbd_request, kref);
	struct drbd_resource *resource = req->device->resource;
	struct drbd_request *destroy_next;
	struct drbd_device *device;
	struct drbd_peer_device *peer_device;
	unsigned int s;
	bool was_last_ref;

	lockdep_assert_held(&resource->state_rwlock);
	lockdep_assert_irqs_disabled();

 tail_recursion:
	was_last_ref = false;
	device = req->device;
	s = req->local_rq_state;

#ifdef CONFIG_DRBD_TIMING_STATS
	if (s & RQ_WRITE && req->i.size != 0) {
		spin_lock(&device->timing_lock); /* local irq already disabled */
		device->reqs++;
		ktime_aggregate(device, req, in_actlog_kt);
		ktime_aggregate(device, req, pre_submit_kt);
		for_each_peer_device(peer_device, device) {
			int node_id = peer_device->node_id;
			unsigned ns = req->net_rq_state[node_id];
			if (!(ns & RQ_NET_MASK))
				continue;
			ktime_aggregate_pd(peer_device, node_id, req, pre_send_kt);
			ktime_aggregate_pd(peer_device, node_id, req, acked_kt);
			ktime_aggregate_pd(peer_device, node_id, req, net_done_kt);
		}
		spin_unlock(&device->timing_lock);
	}
#endif

	/* paranoia */
	for_each_peer_device(peer_device, device) {
		unsigned ns = req->net_rq_state[peer_device->node_id];
		if (!(ns & RQ_NET_MASK))
			continue;
		if (ns & RQ_NET_DONE)
			continue;

		drbd_err(device,
			"drbd_req_destroy: Logic BUG rq_state: (0:%x, %d:%x), completion_ref = %d\n",
			s, peer_device->node_id, ns, atomic_read(&req->completion_ref));
		return;
	}

	/* more paranoia */
	if ((req->master_bio && !(s & RQ_POSTPONED)) ||
		atomic_read(&req->completion_ref) || (s & RQ_LOCAL_PENDING)) {
		drbd_err(device, "drbd_req_destroy: Logic BUG rq_state: %x, completion_ref = %d\n",
				s, atomic_read(&req->completion_ref));
		return;
	}

	spin_lock(&resource->tl_update_lock); /* local irq already disabled */
	destroy_next = req->destroy_next;
	list_del_rcu(&req->tl_requests);
	if (resource->tl_previous_write == req)
		resource->tl_previous_write = NULL;
	spin_unlock(&resource->tl_update_lock);

	/* finally remove the request from the conflict detection
	 * respective block_id verification interval tree. */
	if (!drbd_interval_empty(&req->i)) {
		struct rb_root *root;

		if (s & RQ_WRITE)
			root = &device->requests;
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
		struct drbd_request *peer_ack_req;

		spin_lock(&resource->peer_ack_lock); /* local irq already disabled */
		peer_ack_req = resource->peer_ack_req;
		if (peer_ack_req) {
			if (peer_ack_differs(req, peer_ack_req) ||
			    (was_last_ref && atomic_read(&device->ap_actlog_cnt)) ||
			    peer_ack_window_full(req)) {
				drbd_queue_peer_ack(resource, peer_ack_req);
				peer_ack_req = NULL;
			} else
				call_rcu(&peer_ack_req->rcu, drbd_reclaim_req);
		}
		resource->peer_ack_req = req;

		if (!peer_ack_req)
			resource->last_peer_acked_dagtag = req->dagtag_sector;
		spin_unlock(&resource->peer_ack_lock);

		mod_timer(&resource->peer_ack_timer,
			  jiffies + resource->res_opts.peer_ack_delay * HZ / 1000);
	} else
		call_rcu(&req->rcu, drbd_reclaim_req);

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

bool start_new_tl_epoch(struct drbd_resource *resource)
{
	unsigned long flags;
	bool new_epoch_started;

	spin_lock_irqsave(&resource->current_tle_lock, flags);
	/* no point closing an epoch, if it is empty, anyways. */
	if (resource->current_tle_writes == 0) {
		new_epoch_started = false;
	} else {
		resource->current_tle_writes = 0;
		atomic_inc(&resource->current_tle_nr);
		wake_all_senders(resource);
		new_epoch_started = true;
	}
	spin_unlock_irqrestore(&resource->current_tle_lock, flags);

	return new_epoch_started;
}

void complete_master_bio(struct drbd_device *device,
		struct bio_and_error *m)
{
	int rw = bio_data_dir(m->bio);
	if (unlikely(m->error))
		m->bio->bi_status = errno_to_blk_status(m->error);
	bio_endio(m->bio);
	dec_ap_bio(device, rw);
}

static void queue_conflicting_resync_write(
		struct conflict_worker *submit_conflict, struct drbd_interval *i)
{
	struct drbd_peer_request *peer_req = container_of(i, struct drbd_peer_request, i);

	list_add_tail(&peer_req->w.list, &submit_conflict->resync_writes);
}

static void queue_conflicting_resync_read(
		struct conflict_worker *submit_conflict, struct drbd_interval *i)
{
	struct drbd_peer_request *peer_req = container_of(i, struct drbd_peer_request, i);

	list_add_tail(&peer_req->w.list, &submit_conflict->resync_reads);
}

static void queue_conflicting_write(
		struct conflict_worker *submit_conflict, struct drbd_interval *i)
{
	struct drbd_request *req = container_of(i, struct drbd_request, i);

	list_add_tail(&req->list, &submit_conflict->writes);
}

static void queue_conflicting_peer_write(
		struct conflict_worker *submit_conflict, struct drbd_interval *i)
{
	struct drbd_peer_request *peer_req = container_of(i, struct drbd_peer_request, i);

	list_add_tail(&peer_req->w.list, &submit_conflict->peer_writes);
}

/* Queue any conflicting requests in this interval to be submitted. */
void drbd_release_conflicts(struct drbd_device *device, struct drbd_interval *release_interval)
{
	struct conflict_worker *submit_conflict = &device->submit_conflict;
	struct drbd_interval *i;
	bool any_queued = false;

	lockdep_assert_held(&device->interval_lock);

	drbd_for_each_overlap(i, &device->requests, release_interval->sector, release_interval->size) {
		if (test_bit(INTERVAL_SUBMITTED, &i->flags))
			continue;

		/* If we are waiting for a reply from the peer, then there is
		 * no need to process the conflict. */
		if (test_bit(INTERVAL_SENT, &i->flags) && !test_bit(INTERVAL_RECEIVED, &i->flags))
			continue;

		dynamic_drbd_dbg(device,
				"%s %s request at %llus+%u after conflict with %llus+%u\n",
				test_bit(INTERVAL_SUBMIT_CONFLICT_QUEUED, &i->flags) ? "Already queued" : "Queue",
				drbd_interval_type_str(i),
				(unsigned long long) i->sector, i->size,
				(unsigned long long) release_interval->sector, release_interval->size);

		if (test_bit(INTERVAL_SUBMIT_CONFLICT_QUEUED, &i->flags))
			continue;

		/* Verify requests never wait for conflicting intervals. If
		 * there are no conflicts, they are marked direcly as
		 * submitted. Hence we should not see any here. */
		if (unlikely(drbd_interval_is_verify(i))) {
			if (drbd_ratelimit())
				drbd_err(device, "Found verify request that was not yet submitted\n");
			continue;
		}

		set_bit(INTERVAL_SUBMIT_CONFLICT_QUEUED, &i->flags);

		spin_lock(&submit_conflict->lock);
		/* Queue the request regardless of whether other conflicts
		 * remain. The conflict submitter will only actually submit the
		 * request if there are no conflicts. */
		switch (i->type) {
			case INTERVAL_LOCAL_WRITE:
				queue_conflicting_write(submit_conflict, i);
				break;
			case INTERVAL_PEER_WRITE:
				queue_conflicting_peer_write(submit_conflict, i);
				break;
			case INTERVAL_RESYNC_WRITE:
				queue_conflicting_resync_write(submit_conflict, i);
				break;
			case INTERVAL_RESYNC_READ:
				queue_conflicting_resync_read(submit_conflict, i);
				break;
			default:
				BUG();
		}
		spin_unlock(&submit_conflict->lock);

		any_queued = true;
	}

	if (any_queued)
		queue_work(submit_conflict->wq, &submit_conflict->worker);
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
	unsigned long flags;
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
		unsigned ns = req->net_rq_state[peer_device->node_id];
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
			 s, peer_device->node_id, ns, atomic_read(&req->completion_ref));
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
	 * We simply compare the request epoch number with the current
	 * transfer log epoch number.
	 * With very specific timing, this may cause unnecessary barriers
	 * to be sent, but that is harmless.
	 *
	 * There is no need to close the transfer log epoch for empty flushes.
	 * The completion of the previous requests had the required effect on
	 * the peers already.
	 */
	if (bio_data_dir(req->master_bio) == WRITE &&
	    likely(req->i.size != 0) &&
	    req->epoch == atomic_read(&device->resource->current_tle_nr))
		start_new_tl_epoch(device->resource);

	/* Update disk stats */
	bio_end_io_acct(req->master_bio, req->start_jif);

	if (device->cached_err_io) {
		ok = 0;
		req->local_rq_state &= ~RQ_POSTPONED;
	} else if (!ok &&
		   bio_op(req->master_bio) == REQ_OP_READ &&
		   !(req->master_bio->bi_opf & REQ_RAHEAD) &&
		   !list_empty(&req->tl_requests)) {
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
		req->local_rq_state |= RQ_POSTPONED;
	}

	if (!(req->local_rq_state & RQ_POSTPONED)) {
		struct drbd_resource *resource = device->resource;
		bool quorum =
			resource->res_opts.on_no_quorum == ONQ_IO_ERROR ?
			resource->cached_all_devices_have_quorum : true;

		m->error = ok && quorum ? 0 : (error ?: -EIO);
		m->bio = req->master_bio;
		req->master_bio = NULL;

		spin_lock_irqsave(&device->interval_lock, flags);
		/* We leave it in the tree, to be able to verify later
		 * write-acks in protocol != C during resync.
		 * But we mark it as "complete", so it won't be counted as
		 * conflict in a multi-primary setup. */
		set_bit(INTERVAL_COMPLETED, &req->i.flags);
		if (req->local_rq_state & RQ_WRITE)
			drbd_release_conflicts(device, &req->i);
		spin_unlock_irqrestore(&device->interval_lock, flags);
	}

	/* Either we are about to complete to upper layers,
	 * or we will restart this request.
	 * In either case, the request object will be destroyed soon,
	 * so better remove it from all lists. */
	spin_lock_irqsave(&device->pending_completion_lock, flags);
	list_del_init(&req->req_pending_master_completion);
	spin_unlock_irqrestore(&device->pending_completion_lock, flags);
}

static void drbd_req_put_completion_ref(struct drbd_request *req, struct bio_and_error *m, int put)
{
	D_ASSERT(req->device, m || (req->local_rq_state & RQ_POSTPONED));

	lockdep_assert_held(&req->device->resource->state_rwlock);

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

void drbd_set_pending_out_of_sync(struct drbd_peer_device *peer_device)
{
	struct drbd_device *device = peer_device->device;
	struct drbd_resource *resource = device->resource;
	const int node_id = peer_device->node_id;
	struct drbd_request *req;

	rcu_read_lock();
	list_for_each_entry_rcu(req, &resource->transfer_log, tl_requests) {
		unsigned int local_rq_state, net_rq_state;

		/* This is similar to the bitmap modification performed in
		 * drbd_req_destroy(), but simplified for this special case. */

		spin_lock_irq(&req->rq_lock);
		local_rq_state = req->local_rq_state;
		net_rq_state = req->net_rq_state[node_id];
		spin_unlock_irq(&req->rq_lock);

		if (!(local_rq_state & RQ_WRITE))
			continue;

		if ((local_rq_state & (RQ_POSTPONED|RQ_LOCAL_MASK|RQ_NET_MASK)) == RQ_POSTPONED)
			continue;

		if (!req->i.size)
			continue;

		if (net_rq_state & RQ_NET_OK)
			continue;

		drbd_set_out_of_sync(peer_device, req->i.sector, req->i.size);
	}
	rcu_read_unlock();
}

static void advance_conn_req_next(struct drbd_connection *connection, struct drbd_request *req)
{
	struct drbd_request *found_req = NULL;
	/* Only the sender thread comes here. No other caller context of req_mod() ever arrives here */
	if (connection->todo.req_next != req)
		return;
	rcu_read_lock();
	list_for_each_entry_continue_rcu(req, &connection->resource->transfer_log, tl_requests) {
		const unsigned s = req->net_rq_state[connection->peer_node_id];
		/* Found a request which is for this peer but not yet queued.
		 * Do not skip past it. */
		if (unlikely(s & RQ_NET_PENDING && !(s & (RQ_NET_QUEUED|RQ_NET_SENT))))
			break;

		connection->send.seen_dagtag_sector = req->dagtag_sector;
		if (likely(s & RQ_NET_QUEUED)) {
			found_req = req;
			break;
		}
	}
	rcu_read_unlock();
	connection->todo.req_next = found_req;
}

/**
 * set_cache_ptr_if_null() - Set caching pointer to given request if not currently set.
 * @cache_ptr: Pointer to set.
 * @req: Request to potentially set the pointer to.
 *
 * The caching pointer system is designed to track the oldest request in the
 * transfer log fulfilling some condition. In particular, a combination of
 * flags towards a given peer. This condition must guarantee that the request
 * will not be destroyed.
 *
 * This system is implemented by set_cache_ptr_if_null() and
 * advance_cache_ptr(). A request must be in the transfer log and fulfil the
 * condition before set_cache_ptr_if_null() is called. If
 * set_cache_ptr_if_null() is called before this request is in the transfer log
 * or before it fulfils the condition, the pointer may be advanced past this
 * request, or unset, which also has the effect of skipping the request.
 *
 * Once the condition is no longer fulfilled for a request, advance_cache_ptr()
 * must be called. If the caching pointer currently points to this request,
 * this will advance it to the next request fulfilling the condition.
 *
 * set_cache_ptr_if_null() may be called concurrently with itself and with
 * advance_cache_ptr().
 */
static void set_cache_ptr_if_null(struct drbd_request **cache_ptr, struct drbd_request *req)
{
	struct drbd_request *prev_req, *old_req = NULL;

	rcu_read_lock();
	prev_req = cmpxchg(cache_ptr, old_req, req);
	while (prev_req != old_req) {
		if (prev_req && req->dagtag_sector > prev_req->dagtag_sector)
			break;
		old_req = prev_req;
		prev_req = cmpxchg(cache_ptr, old_req, req);
	}
	rcu_read_unlock();
}

/* See set_cache_ptr_if_null(). */
static void advance_cache_ptr(struct drbd_connection *connection,
			      struct drbd_request __rcu **cache_ptr, struct drbd_request *req,
			      unsigned int is_set, unsigned int is_clear)
{
	struct drbd_request *old_req;
	struct drbd_request *found_req = NULL;

	/*
	 * Prevent concurrent updates of the same caching pointer. Otherwise if
	 * this function is called concurrently for a given caching pointer,
	 * the call for the older request may advance the pointer to the newer
	 * request, although the newer request has concurrently been modified
	 * such that it no longer fulfils the condition.
	 */
	spin_lock(&connection->advance_cache_ptr_lock); /* local IRQ already disabled */

	rcu_read_lock();
	old_req = rcu_dereference(*cache_ptr);
	if (old_req != req) {
		rcu_read_unlock();
		spin_unlock(&connection->advance_cache_ptr_lock);
		return;
	}
	list_for_each_entry_continue_rcu(req, &connection->resource->transfer_log, tl_requests) {
		const unsigned s = READ_ONCE(req->net_rq_state[connection->peer_node_id]);
		if (!(s & RQ_NET_MASK))
			continue;
		if (((s & is_set) == is_set) && !(s & is_clear)) {
			found_req = req;
			break;
		}
	}

	cmpxchg(cache_ptr, old_req, found_req);
	rcu_read_unlock();

	spin_unlock(&connection->advance_cache_ptr_lock);
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
	unsigned old_local, old_net = 0;
	unsigned set_local = set & RQ_STATE_0_MASK;
	unsigned clear_local = clear & RQ_STATE_0_MASK;
	int c_put = 0;
	const int idx = peer_device ? peer_device->node_id : -1;
	struct drbd_connection *connection = NULL;
	bool unchanged;

	set &= ~RQ_STATE_0_MASK;
	clear &= ~RQ_STATE_0_MASK;

	if (idx == -1) {
		/* do not try to manipulate net state bits
		 * without an associated state slot! */
		BUG_ON(set);
		BUG_ON(clear);
	}

	/* apply */
	spin_lock(&req->rq_lock); /* local IRQ already disabled */

	old_local = req->local_rq_state;
	req->local_rq_state &= ~clear_local;
	req->local_rq_state |= set_local;

	if (idx != -1) {
		old_net = req->net_rq_state[idx];
		WRITE_ONCE(req->net_rq_state[idx], (req->net_rq_state[idx] & ~clear) | set);
		connection = peer_device->connection;
	}

	/* no change? */
	unchanged = req->local_rq_state == old_local &&
	  (idx == -1 || req->net_rq_state[idx] == old_net);

	if (unchanged) {
		spin_unlock(&req->rq_lock);
		return;
	}

	/* intent: get references */

	kref_get(&req->kref);

	if (!(old_local & RQ_LOCAL_PENDING) && (set_local & RQ_LOCAL_PENDING))
		atomic_inc(&req->completion_ref);

	if (!(old_net & RQ_NET_PENDING) && (set & RQ_NET_PENDING)) {
		inc_ap_pending(peer_device);
		atomic_inc(&req->completion_ref);
	}

	if (!(old_net & RQ_NET_QUEUED) && (set & RQ_NET_QUEUED)) {
		set_cache_ptr_if_null(&connection->req_not_net_done, req);
		atomic_inc(&req->completion_ref);
		/* This completion ref is necessary to avoid premature completion
		   in case a WRITE_ACKED_BY_PEER comes in before the sender can do
		   HANDED_OVER_TO_NETWORK. */
	}

	if (!(old_net & RQ_EXP_BARR_ACK) && (set & RQ_EXP_BARR_ACK))
		kref_get(&req->kref); /* wait for the DONE */

	if (!(old_net & RQ_NET_SENT) && (set & RQ_NET_SENT)) {
		/* potentially already completed in the ack_receiver thread */
		if (!(old_net & RQ_NET_DONE))
			atomic_add(req_payload_sectors(req), &peer_device->connection->ap_in_flight);
		if (req->net_rq_state[idx] & RQ_NET_PENDING)
			set_cache_ptr_if_null(&connection->req_ack_pending, req);
	}

	if (!(old_local & RQ_COMPLETION_SUSP) && (set_local & RQ_COMPLETION_SUSP))
		atomic_inc(&req->completion_ref);

	spin_unlock(&req->rq_lock);

	/* progress: put references */

	if ((old_local & RQ_COMPLETION_SUSP) && (clear_local & RQ_COMPLETION_SUSP))
		++c_put;

	if (!(old_local & RQ_LOCAL_ABORTED) && (set_local & RQ_LOCAL_ABORTED)) {
		D_ASSERT(req->device, req->local_rq_state & RQ_LOCAL_PENDING);
		++c_put;
	}

	if ((old_local & RQ_LOCAL_PENDING) && (clear_local & RQ_LOCAL_PENDING)) {
		struct drbd_device *device = req->device;

		if (req->local_rq_state & RQ_LOCAL_ABORTED)
			kref_put(&req->kref, drbd_req_destroy);
		else
			++c_put;
		spin_lock(&device->pending_completion_lock); /* local irq already disabled */
		list_del_init(&req->req_pending_local);
		spin_unlock(&device->pending_completion_lock);
	}

	if ((old_net & RQ_NET_PENDING) && (clear & RQ_NET_PENDING)) {
		dec_ap_pending(peer_device);
		++c_put;
		ktime_get_accounting(req->acked_kt[peer_device->node_id]);
		advance_cache_ptr(connection, &connection->req_ack_pending,
				  req, RQ_NET_SENT | RQ_NET_PENDING, 0);
	}

	if ((old_net & RQ_NET_QUEUED) && (clear & RQ_NET_QUEUED)) {
		++c_put;
		advance_conn_req_next(connection, req);
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
				mod_timer(&pd->start_resync_timer, jiffies + HZ);
			}
		}

		/* in ahead/behind mode, or just in case,
		 * before we finally destroy this request,
		 * the caching pointers must not reference it anymore */
		advance_conn_req_next(connection, req);
		advance_cache_ptr(connection, &connection->req_ack_pending,
				  req, RQ_NET_SENT | RQ_NET_PENDING, 0);
		advance_cache_ptr(connection, &connection->req_not_net_done,
				  req, 0, RQ_NET_DONE);
	}

	/* potentially complete and destroy */
	drbd_req_put_completion_ref(req, m, c_put);
	kref_put(&req->kref, drbd_req_destroy);
}

static void drbd_report_io_error(struct drbd_device *device, struct drbd_request *req)
{
	if (!drbd_ratelimit())
		return;

	drbd_warn(device, "local %s IO error sector %llu+%u on %pg\n",
		  (req->local_rq_state & RQ_WRITE) ? "WRITE" : "READ",
		  (unsigned long long)req->i.sector,
		  req->i.size >> 9,
		  device->ldev->backing_bdev);
}

static int drbd_protocol_state_bits(struct drbd_connection *connection)
{
	struct net_conf *nc;
	int p;

	rcu_read_lock();
	nc = rcu_dereference(connection->transport.net_conf);
	p = nc->wire_protocol;
	rcu_read_unlock();

	return p == DRBD_PROT_C ? RQ_EXP_WRITE_ACK :
		p == DRBD_PROT_B ? RQ_EXP_RECEIVE_ACK : 0;

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
 *  happen with the state_rwlock read lock held,
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
	unsigned long flags;
	int p;
	int idx;

	lockdep_assert_held(&device->resource->state_rwlock);

	if (m)
		m->bio = NULL;

	idx = peer_device ? peer_device->node_id : -1;

	switch (what) {
	default:
		drbd_err(device, "LOGIC BUG in %s:%u\n", __FILE__ , __LINE__);
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
		mod_rq_state(req, m, peer_device, RQ_LOCAL_PENDING, RQ_LOCAL_COMPLETED);
		break;

	case READ_COMPLETED_WITH_ERROR:
		drbd_set_all_out_of_sync(device, req->i.sector, req->i.size);
		drbd_report_io_error(device, req);
		fallthrough;
	case READ_AHEAD_COMPLETED_WITH_ERROR:
		mod_rq_state(req, m, peer_device, RQ_LOCAL_PENDING, RQ_LOCAL_COMPLETED);
		break;

	case DISCARD_COMPLETED_NOTSUPP:
	case DISCARD_COMPLETED_WITH_ERROR:
		/* I'd rather not detach from local disk just because it
		 * failed a REQ_OP_DISCARD. */
		mod_rq_state(req, m, peer_device, RQ_LOCAL_PENDING, RQ_LOCAL_COMPLETED);
		break;

	case NEW_NET_READ:
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
		spin_lock_irqsave(&device->interval_lock, flags);
		drbd_insert_interval(&device->read_requests, &req->i);
		spin_unlock_irqrestore(&device->interval_lock, flags);

		D_ASSERT(device, !(req->net_rq_state[idx] & RQ_NET_MASK));
		D_ASSERT(device, !(req->local_rq_state & RQ_LOCAL_MASK));
		mod_rq_state(req, m, peer_device, 0, RQ_NET_PENDING);
		break;

	case NEW_NET_WRITE:
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

		D_ASSERT(device, !(req->net_rq_state[idx] & RQ_NET_MASK));

		/* queue work item to send data */
		mod_rq_state(req, m, peer_device, 0, RQ_NET_PENDING|RQ_EXP_BARR_ACK|
				drbd_protocol_state_bits(peer_device->connection));

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

	case NEW_NET_OOS:
		mod_rq_state(req, m, peer_device, 0, RQ_NET_PENDING);
		break;

	case ADDED_TO_TRANSFER_LOG:
		mod_rq_state(req, m, peer_device, 0, RQ_NET_QUEUED);
		break;

	case SEND_CANCELED:
	case SEND_FAILED:
		/* Just update flags so it is no longer marked as on the sender
		 * queue; real cleanup will be done from
		 * tl_walk(,CONNECTION_LOST*). */
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
		/* No longer PENDING or QUEUED, so is now DONE
		 * as far as this connection is concerned. */
		mod_rq_state(req, m, peer_device, RQ_NET_PENDING|RQ_NET_QUEUED, RQ_NET_DONE);
		break;

	case CONNECTION_LOST:
	case CONNECTION_LOST_WHILE_SUSPENDED:
		/* Only apply to requests that were for this peer but not done. */
		if (!(req->net_rq_state[idx] & RQ_NET_MASK) || req->net_rq_state[idx] & RQ_NET_DONE)
			break;

		/* For protocol A, or when not suspended, we consider the
		 * request to be lost towards this peer.
		 *
		 * Protocol B&C requests are kept while suspended because
		 * resending is allowed. If such a request is pending to this
		 * peer, we suspend its completion until IO is resumed. This is
		 * a conservative simplification. We could complete it while
		 * suspended once we know it has been received by "enough"
		 * peers. However, we do not track that.
		 *
		 * If the request is no longer pending to this peer, then we
		 * have already received the corresponding ack. The request may
		 * complete as far as this peer is concerned. */
		if (what == CONNECTION_LOST ||
				!(req->net_rq_state[idx] & (RQ_EXP_RECEIVE_ACK|RQ_EXP_WRITE_ACK)))
			mod_rq_state(req, m, peer_device, RQ_NET_PENDING|RQ_NET_OK, RQ_NET_DONE);
		else if (req->net_rq_state[idx] & RQ_NET_PENDING)
			mod_rq_state(req, m, peer_device, 0, RQ_COMPLETION_SUSP);
		break;

	case WRITE_ACKED_BY_PEER_AND_SIS:
		spin_lock_irqsave(&req->rq_lock, flags);
		req->net_rq_state[idx] |= RQ_NET_SIS;
		spin_unlock_irqrestore(&req->rq_lock, flags);
		fallthrough;
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

	case NEG_ACKED:
		mod_rq_state(req, m, peer_device, RQ_NET_OK|RQ_NET_PENDING,
			     (req->local_rq_state & RQ_WRITE) ? 0 : RQ_NET_DONE);
		break;

	case COMPLETION_RESUMED:
		mod_rq_state(req, m, peer_device, RQ_COMPLETION_SUSP, 0);
		break;

	case CANCEL_SUSPENDED_IO:
		/* Only apply to requests that were for this peer but not done. */
		if (!(req->net_rq_state[idx] & RQ_NET_MASK) || req->net_rq_state[idx] & RQ_NET_DONE)
			break;

		/* CONNECTION_LOST_WHILE_SUSPENDED followed by
		 * CANCEL_SUSPENDED_IO should be essentially the same as
		 * CONNECTION_LOST. Make the corresponding changes. The
		 * RQ_COMPLETION_SUSP flag is handled by COMPLETION_RESUMED. */
		mod_rq_state(req, m, peer_device, RQ_NET_PENDING|RQ_NET_OK, RQ_NET_DONE);
		break;

	case RESEND:
		/* If RQ_NET_OK is already set, we got a P_WRITE_ACK or P_RECV_ACK
		   before the connection loss (B&C only); only P_BARRIER_ACK
		   (or the local completion?) was missing when we suspended.
		   Throwing them out of the TL here by pretending we got a BARRIER_ACK.
		   During connection handshake, we ensure that the peer was not rebooted.

		   Protocol A requests always have RQ_NET_OK removed when the
		   connection is lost, so this will never apply to them.

		   Resending is only allowed on synchronous connections,
		   where all requests not yet completed to upper layers would
		   be in the same "reorder-domain", there can not possibly be
		   any dependency between incomplete requests, and we are
		   allowed to complete this one "out-of-sequence".
		 */
		if (req->net_rq_state[idx] & RQ_NET_OK)
			goto barrier_acked;

		/* Only apply to requests that are pending a response from
		 * this peer. */
		if (!(req->net_rq_state[idx] & RQ_NET_PENDING))
			break;

		D_ASSERT(device, !(req->net_rq_state[idx] & RQ_NET_QUEUED));
		mod_rq_state(req, m, peer_device, RQ_NET_SENT, RQ_NET_QUEUED);
		break;

	case BARRIER_ACKED:
barrier_acked:
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
		/* As this is called for all requests within a matching epoch,
		 * we need to filter, and only set RQ_NET_DONE for those that
		 * have actually been on the wire. */
		if (req->net_rq_state[idx] & RQ_NET_MASK)
			mod_rq_state(req, m, peer_device, 0, RQ_NET_DONE);
		break;

	case DATA_RECEIVED:
		D_ASSERT(device, req->net_rq_state[idx] & RQ_NET_PENDING);
		mod_rq_state(req, m, peer_device, RQ_NET_PENDING, RQ_NET_OK|RQ_NET_DONE);
		break;

	case BARRIER_SENT:
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
	int stripe_shift;

	switch (rbm) {
	case RB_CONGESTED_REMOTE:
		/* originally, this used the bdi congestion framework,
		 * but that was removed in linux 5.18.
		 * so just never report the lower device as congested. */
		return false;
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

static void __maybe_pull_ahead(struct drbd_device *device, struct drbd_connection *connection)
{
	struct net_conf *nc;
	bool congested = false;
	enum drbd_on_congestion on_congestion;
	u32 cong_fill = 0, cong_extents = 0;
	struct drbd_peer_device *peer_device = conn_peer_device(connection, device->vnr);

	lockdep_assert_held(&device->resource->state_rwlock);

	if (connection->agreed_pro_version < 96)
		return;

	nc = rcu_dereference(connection->transport.net_conf);
	if (nc) {
		on_congestion = nc->on_congestion;
		cong_fill = nc->cong_fill;
		cong_extents = nc->cong_extents;
	} else {
		on_congestion = OC_BLOCK;
	}
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

	if (test_and_set_bit(HANDLING_CONGESTION, &peer_device->flags))
		goto out;

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
		set_bit(CONN_CONGESTED, &connection->flags);
		drbd_peer_device_post_work(peer_device, HANDLE_CONGESTION);
	} else {
		clear_bit(HANDLING_CONGESTION, &peer_device->flags);
	}
out:
	put_ldev(device);
}

static void maybe_pull_ahead(struct drbd_device *device)
{
	struct drbd_connection *connection;

	rcu_read_lock();
	for_each_connection_rcu(connection, device->resource)
		if (connection->cstate[NOW] == C_CONNECTED)
			__maybe_pull_ahead(device, connection);
	rcu_read_unlock();
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
	enum drbd_disk_state peer_disk_state = peer_device->disk_state[NOW];
	enum drbd_repl_state repl_state = peer_device->repl_state[NOW];

	return repl_state == L_AHEAD ||
		repl_state == L_WF_BITMAP_S ||
		(peer_disk_state == D_OUTDATED && repl_state >= L_ESTABLISHED);

	/* proto 96 check omitted, there was no L_AHEAD back then,
	 * peer disk was never Outdated while connection was established,
	 * and IO was frozen during bitmap exchange */
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

static int drbd_process_empty_flush(struct drbd_request *req)
{
	struct drbd_device *device = req->device;
	struct drbd_peer_device *peer_device;
	int count = 0;

	for_each_peer_device(peer_device, device) {
		/* When a flush is submitted, the expectation is that the data
		 * is written somewhere in a usable form. Hence only
		 * D_UP_TO_DATE peers are included and not all peers that
		 * receive the data. */
		if (peer_device->disk_state[NOW] == D_UP_TO_DATE) {
			++count;

			/* An empty flush indicates that all previously
			 * completed requests should be written out to stable
			 * storage. Request completion already triggers a
			 * barrier to be sent and the current epoch closed. The
			 * barrier causes the data to be written out unless
			 * that is configured not to be necessary.
			 *
			 * Hence there is nothing more to be done to cause the
			 * writing out to persistent storage which was
			 * requested. We just mark the request so that we know
			 * that a flush has effectively occurred on this peer
			 * so that we can complete it successfully.
			 *
			 * We _should_ wait for any outstanding barriers to
			 * protocol C peers to be acked before completing this
			 * request, so that we are sure that the previously
			 * completed requests have really been written out
			 * there too. However, DRBD has never yet implemented
			 * this. */
			_req_mod(req, BARRIER_SENT, peer_device);
		}
	}

	return count;
}

/* returns the number of connections expected to actually write this data,
 * which does NOT include those that we are L_AHEAD for. */
static int drbd_process_write_request(struct drbd_request *req)
{
	struct drbd_device *device = req->device;
	struct drbd_peer_device *peer_device;
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
			_req_mod(req, NEW_NET_WRITE, peer_device);
		} else
			_req_mod(req, NEW_NET_OOS, peer_device);
	}

	return count;
}

static void drbd_queue_request(struct drbd_request *req)
{
	struct drbd_device *device = req->device;
	struct drbd_peer_device *peer_device;

	for_each_peer_device(peer_device, device) {
		if (req->net_rq_state[peer_device->node_id] & RQ_NET_PENDING)
			_req_mod(req, ADDED_TO_TRANSFER_LOG, peer_device);
	}
}

static void drbd_process_discard_or_zeroes_req(struct drbd_request *req, int flags)
{
	int err = drbd_issue_discard_or_zero_out(req->device,
				req->i.sector, req->i.size >> 9, flags);
	if (err)
		req->private_bio->bi_status = BLK_STS_IOERR;
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
	spin_lock_irq(&device->pending_completion_lock);
	list_add_tail(&req->req_pending_master_completion,
			&device->pending_master_completion[1 /* WRITE */]);
	spin_unlock_irq(&device->pending_completion_lock);
	spin_lock(&device->submit.lock);
	list_add_tail(&req->list, &device->submit.writes);
	spin_unlock(&device->submit.lock);
	queue_work(device->submit.wq, &device->submit.worker);
	/* do_submit() may sleep internally on al_wait, too */
	wake_up(&device->al_wait);
}

static void drbd_req_in_actlog(struct drbd_request *req)
{
	req->local_rq_state |= RQ_IN_ACT_LOG;
	ktime_get_accounting(req->in_actlog_kt);
	atomic_sub(interval_to_al_extents(&req->i), &req->device->wait_for_actlog_ecnt);
}

/* returns the new drbd_request pointer, if the caller is expected to submit it
 * (to save latency), or NULL if we queued the request on the submitter thread.
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

	if (get_ldev(device)) {
		req->private_bio = bio_alloc_clone(device->ldev->backing_bdev, bio, GFP_NOIO, &drbd_io_bio_set);
		req->private_bio->bi_private = req;
		req->private_bio->bi_end_io = drbd_request_endio;
	}

	ktime_get_accounting_assign(req->start_kt, start_kt);

	if (rw != WRITE || req->i.size == 0)
		return req;

	/* Let the activity log know we are about to use it...
	 * FIXME
	 * Needs to slow down to not congest on the activity log, in case we
	 * have multiple primaries and the peer sends huge scattered epochs.
	 * See also how peer_requests are handled
	 * in receive_Data() { ... drbd_wait_for_activity_log_extents(); ... }
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
	struct drbd_request *req = plug->most_recent_req;
	struct drbd_resource *resource = req->device->resource;

	kfree(cb);
	if (!req)
		return;

	read_lock_irq(&resource->state_rwlock);
	/* In case the sender did not process it yet, raise the flag to
	 * have it followed with P_UNPLUG_REMOTE just after. */
	spin_lock(&req->rq_lock);
	req->local_rq_state |= RQ_UNPLUG;
	spin_unlock(&req->rq_lock);
	/* but also queue a generic unplug */
	drbd_queue_unplug(req->device);
	kref_put(&req->kref, drbd_req_destroy);
	read_unlock_irq(&resource->state_rwlock);
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
	/* Will be sent to some peer. */
	kref_get(&req->kref);
	plug->most_recent_req = req;
	if (tmp)
		kref_put(&tmp->kref, drbd_req_destroy);
}

static void drbd_send_and_submit(struct drbd_request *req)
{
	struct drbd_device *device = req->device;
	struct drbd_resource *resource = device->resource;
	struct drbd_peer_device *peer_device = NULL; /* for read */
	const int rw = bio_data_dir(req->master_bio);
	struct bio_and_error m = { NULL, };
	bool no_remote = false;
	bool submit_private_bio = false;

	read_lock_irq(&resource->state_rwlock);

	if (rw == WRITE) {
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

	if (rw == WRITE) {
		if (!may_do_writes(device)) {
			if (req->private_bio) {
				bio_put(req->private_bio);
				req->private_bio = NULL;
				put_ldev(device);
			}
			goto nodata;
		}
	} else {
		/* We fail READ early, if we can not serve it.
		 * We must do this before req is registered on any lists.
		 * Otherwise, drbd_req_complete() will queue failed READ for retry. */
		peer_device = find_peer_device_for_read(req);
		if (!peer_device && !req->private_bio)
			goto nodata;
	}

	spin_lock(&resource->tl_update_lock); /* local irq already disabled */
	if (rw == WRITE) {
		/* Update dagtag_sector before determining current_tle_nr so
		 * that senders can detect if there are requests currently
		 * being submitted. Updates are protected by tl_update_lock,
		 * but reads are not, so WRITE_ONCE(). */
		WRITE_ONCE(resource->dagtag_sector, resource->dagtag_sector + (req->i.size >> 9));
		/* Ensure that the written value is visible to the senders. */
		smp_wmb();
	}
	req->dagtag_sector = resource->dagtag_sector;

	spin_lock(&resource->current_tle_lock);
	/* which transfer log epoch does this belong to? */
	req->epoch = atomic_read(&resource->current_tle_nr);
	if (rw == WRITE && likely(req->i.size != 0))
		resource->current_tle_writes++;
	spin_unlock(&resource->current_tle_lock);

	/* A size==0 bio can only be an empty flush, which is mapped to a DRBD
	 * P_BARRIER packet. */
	if (unlikely(req->i.size == 0)) {
		/* The only size==0 bios we expect are empty flushes. */
		D_ASSERT(device, req->master_bio->bi_opf & REQ_PREFLUSH);

		if (!drbd_process_empty_flush(req))
			no_remote = true;
	} else {
		if (rw == WRITE) {
			struct drbd_request *prev_write = resource->tl_previous_write;
			resource->tl_previous_write = req;

			if (prev_write) {
				kref_get(&req->kref);
				prev_write->destroy_next = req;
			}

			if (!drbd_process_write_request(req))
				no_remote = true;
		} else {
			if (peer_device)
				_req_mod(req, NEW_NET_READ, peer_device);
			else
				no_remote = true;
		}

		/* req may now be accessed by other threads - do not modify
		 * "immutable" fields after this point */
		list_add_tail_rcu(&req->tl_requests, &resource->transfer_log);

		/* Do this after adding to the transfer log so that the
		 * caching pointer req_not_net_done is set if
		 * necessary. */
		drbd_queue_request(req);
	}
	spin_unlock(&resource->tl_update_lock);

	if (rw == WRITE)
		wake_all_senders(resource);
	else if (peer_device)
		wake_up(&peer_device->connection->sender_work.q_wait);

	if (no_remote == false) {
		struct drbd_plug_cb *plug = drbd_check_plugged(resource);
		if (plug)
			drbd_update_plug(plug, req);
	}

	/* If it took the fast path in drbd_request_prepare, add it here.
	 * The slow path has added it already. */
	spin_lock(&device->pending_completion_lock); /* local irq already disabled */
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
		spin_unlock(&device->pending_completion_lock);
	} else {
		spin_unlock(&device->pending_completion_lock);
		if (no_remote) {
nodata:
			if (drbd_ratelimit())
				drbd_err(req->device, "IO ERROR: neither local nor remote data, sector %llu+%u\n",
					 (unsigned long long)req->i.sector, req->i.size >> 9);
			/* A write may have been queued for send_oos, however.
			 * So we can not simply free it, we must go through drbd_req_put_completion_ref() */
		}
	}

out:
	drbd_req_put_completion_ref(req, &m, 1);
	read_unlock_irq(&resource->state_rwlock);

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

/* Insert the request into the tree of writes. Pass it through to be submitted
 * if possible. Otherwise it will be submitted asynchronously via
 * drbd_release_conflicts once the conflict has been resolved. */
static void drbd_conflict_submit_write(struct drbd_request *req)
{
	struct drbd_device *device = req->device;
	bool conflict = false;

	spin_lock_irq(&device->interval_lock);
	clear_bit(INTERVAL_SUBMIT_CONFLICT_QUEUED, &req->i.flags);
	conflict = drbd_find_conflict(device, &req->i, 0);
	if (drbd_interval_empty(&req->i))
		drbd_insert_interval(&device->requests, &req->i);
	if (!conflict)
		set_bit(INTERVAL_SUBMITTED, &req->i.flags);
	spin_unlock_irq(&device->interval_lock);

	/* If there is a conflict, the request will be submitted once the
	 * conflict has cleared. */
	if (!conflict)
		drbd_send_and_submit(req);
}

static bool inc_ap_bio_cond(struct drbd_device *device, int rw)
{
	int ap_bio_cnt;
	bool rv;

	read_lock_irq(&device->resource->state_rwlock);
	rv = may_inc_ap_bio(device);
	read_unlock_irq(&device->resource->state_rwlock);
	if (!rv)
		return false;

	/* check need for new current uuid _AFTER_ ensuring IO is not suspended via may_inc_ap_bio */
	if (test_bit(NEW_CUR_UUID, &device->flags)) {
		if (!test_and_set_bit(WRITING_NEW_CUR_UUID, &device->flags))
			drbd_device_post_work(device, MAKE_NEW_CUR_UUID);

		return false;
	}

	do {
		unsigned int nr_requests = device->resource->res_opts.nr_requests;

		ap_bio_cnt = atomic_read(&device->ap_bio_cnt[rw]);
		if (ap_bio_cnt >= nr_requests)
			return false;
	} while (atomic_cmpxchg(&device->ap_bio_cnt[rw], ap_bio_cnt, ap_bio_cnt + 1) != ap_bio_cnt);

	return true;
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
	const int rw = bio_data_dir(bio);
	struct drbd_request *req;

	inc_ap_bio(device, bio_data_dir(bio));
	req = drbd_request_prepare(device, bio, start_kt, start_jif);
	if (IS_ERR_OR_NULL(req))
		return;

	if (rw == WRITE)
		drbd_conflict_submit_write(req);
	else
		drbd_send_and_submit(req);
}

/* Work function to submit requests once they are released after conflicts. The
 * queued requests are processed and, if no other conflict is found, submitted. */
void drbd_do_submit_conflict(struct work_struct *ws)
{
	struct drbd_device *device = container_of(ws, struct drbd_device, submit_conflict.worker);
	struct drbd_peer_request *peer_req, *peer_req_tmp;
	struct drbd_request *req, *tmp;
	LIST_HEAD(resync_writes);
	LIST_HEAD(resync_reads);
	LIST_HEAD(writes);
	LIST_HEAD(peer_writes);

	spin_lock_irq(&device->submit_conflict.lock);
	list_splice_init(&device->submit_conflict.resync_writes, &resync_writes);
	list_splice_init(&device->submit_conflict.resync_reads, &resync_reads);
	list_splice_init(&device->submit_conflict.writes, &writes);
	list_splice_init(&device->submit_conflict.peer_writes, &peer_writes);
	spin_unlock_irq(&device->submit_conflict.lock);

	/* Delete the list entries when iterating them so that they can be re-used
	 * for adding them to the conflict lists again once the
	 * submit_conflict_queued flag has been cleared. */

	list_for_each_entry_safe(peer_req, peer_req_tmp, &resync_writes, w.list) {
		list_del_init(&peer_req->w.list);
		if (!test_bit(INTERVAL_SENT, &peer_req->i.flags))
			drbd_conflict_send_resync_request(peer_req);
		else
			drbd_conflict_submit_resync_request(peer_req);
	}

	list_for_each_entry_safe(peer_req, peer_req_tmp, &resync_reads, w.list) {
		list_del_init(&peer_req->w.list);
		drbd_conflict_submit_peer_read(peer_req);
	}

	list_for_each_entry_safe(req, tmp, &writes, list) {
		list_del_init(&req->list);
		drbd_conflict_submit_write(req);
	}

	list_for_each_entry_safe(peer_req, peer_req_tmp, &peer_writes, w.list) {
		list_del_init(&peer_req->w.list);
		drbd_conflict_submit_peer_write(peer_req);
	}
}

/* helpers for do_submit */

struct incoming_pending {
	/* from drbd_submit_bio() or receive_Data() */
	struct list_head incoming;
	/* for non-blocking fill-up # of updates in the transaction */
	struct list_head more_incoming;
	/* to be submitted after next AL-transaction commit */
	struct list_head pending;
	/* need cleanup */
	struct list_head cleanup;
};

struct waiting_for_act_log {
	struct incoming_pending requests;
	struct incoming_pending peer_requests;
};

static void ipb_init(struct incoming_pending *ipb)
{
	INIT_LIST_HEAD(&ipb->incoming);
	INIT_LIST_HEAD(&ipb->more_incoming);
	INIT_LIST_HEAD(&ipb->pending);
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
	list_del_init(&peer_req->w.list);

	err = drbd_submit_peer_request(peer_req);

	if (err)
		drbd_cleanup_after_failed_submit_peer_write(peer_req);
}

static void submit_fast_path(struct drbd_device *device, struct waiting_for_act_log *wfa)
{
	struct blk_plug plug;
	struct drbd_request *req, *tmp;
	struct drbd_peer_request *pr, *pr_tmp;

	blk_start_plug(&plug);
	list_for_each_entry_safe(pr, pr_tmp, &wfa->peer_requests.incoming, w.list) {
		if (!drbd_al_begin_io_fastpath(pr->peer_device->device, &pr->i))
			continue;

		__drbd_submit_peer_request(pr);
	}
	list_for_each_entry_safe(req, tmp, &wfa->requests.incoming, list) {
		const int rw = bio_data_dir(req->master_bio);

		if (rw == WRITE && req->private_bio && req->i.size
				&& !test_bit(AL_SUSPENDED, &device->flags)) {
			if (!drbd_al_begin_io_fastpath(device, &req->i))
				continue;

			drbd_req_in_actlog(req);
			atomic_dec(&device->ap_actlog_cnt);
		}

		list_del_init(&req->list);
		drbd_conflict_submit_write(req);
	}
	blk_finish_plug(&plug);
}

static struct drbd_request *wfa_next_request(struct waiting_for_act_log *wfa)
{
	struct list_head *lh = !list_empty(&wfa->requests.more_incoming) ?
			&wfa->requests.more_incoming: &wfa->requests.incoming;
	return list_first_entry_or_null(lh, struct drbd_request, list);
}

static struct drbd_peer_request *wfa_next_peer_request(struct waiting_for_act_log *wfa)
{
	struct list_head *lh = !list_empty(&wfa->peer_requests.more_incoming) ?
			&wfa->peer_requests.more_incoming: &wfa->peer_requests.incoming;
	return list_first_entry_or_null(lh, struct drbd_peer_request, w.list);
}

static bool prepare_al_transaction_nonblock(struct drbd_device *device,
					    struct waiting_for_act_log *wfa)
{
	struct drbd_peer_request *peer_req;
	struct drbd_request *req;
	bool made_progress = false;
	int err;

	spin_lock_irq(&device->al_lock);

	/* Don't even try, if someone has it locked right now. */
	if (test_bit(__LC_LOCKED, &device->act_log->flags))
		goto out;

	while ((peer_req = wfa_next_peer_request(wfa))) {
		if (peer_req->peer_device->connection->cstate[NOW] < C_CONNECTED) {
			list_move_tail(&peer_req->w.list, &wfa->peer_requests.cleanup);
			made_progress = true;
			continue;
		}
		err = drbd_al_begin_io_nonblock(device, &peer_req->i);
		if (err) {
			if (err != -ENOBUFS && drbd_ratelimit())
				drbd_err(device, "Unexpected error %d from drbd_al_begin_io_nonblock\n", err);
			break;
		}
		list_move_tail(&peer_req->w.list, &wfa->peer_requests.pending);
		made_progress = true;
	}
	while ((req = wfa_next_request(wfa))) {
		ktime_aggregate_delta(device, req->start_kt, before_al_begin_io_kt);
		err = drbd_al_begin_io_nonblock(device, &req->i);
		if (err) {
			if (err != -ENOBUFS && drbd_ratelimit())
				drbd_err(device, "Unexpected error %d from drbd_al_begin_io_nonblock\n", err);
			break;
		}
		list_move_tail(&req->list, &wfa->requests.pending);
		made_progress = true;
	}
 out:
	spin_unlock_irq(&device->al_lock);
	return made_progress;
}

static void send_and_submit_pending(struct drbd_device *device, struct waiting_for_act_log *wfa)
{
	struct blk_plug plug;
	struct drbd_request *req, *tmp;
	struct drbd_peer_request *pr, *pr_tmp;

	blk_start_plug(&plug);
	list_for_each_entry_safe(pr, pr_tmp, &wfa->peer_requests.pending, w.list) {
		__drbd_submit_peer_request(pr);
	}
	list_for_each_entry_safe(req, tmp, &wfa->requests.pending, list) {
		drbd_req_in_actlog(req);
		atomic_dec(&device->ap_actlog_cnt);
		list_del_init(&req->list);
		drbd_conflict_submit_write(req);
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

	spin_lock(&device->submit.lock);
	found_new = !list_empty(&device->submit.writes);
	list_splice_tail_init(&device->submit.writes, reqs);
	found_new |= !list_empty(&device->submit.peer_writes);
	list_splice_tail_init(&device->submit.peer_writes, peer_reqs);
	spin_unlock(&device->submit.lock);

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
			 * That would mean that all (peer-)requests in our
			 * incoming lists target "cold" activity log extents,
			 * all activity log extent slots are have on-going
			 * in-flight IO (are "hot"), and no idle or free slot
			 * is available.
			 *
			 * prepare_to_wait() can internally cause a wake_up()
			 * as well, though, so this may appear to busy-loop
			 * a couple times, but should settle down quickly.
			 *
			 * When application requests make sufficient progress,
			 * some refcount on some extent will eventually drop to
			 * zero, we will be woken up, and can try to move that
			 * now idle extent to "cold", and recycle its slot for
			 * one of the extents we'd like to become hot.
			 */
			prepare_to_wait(&device->al_wait, &wait, TASK_UNINTERRUPTIBLE);

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

			/* Nothing moved to pending, but nothing left on
			 * incoming. Grab new and iterate. */
			grab_new_incoming_requests(device, &wfa, false);
		}
		finish_wait(&device->al_wait, &wait);

		/* If the transaction was full, before all incoming requests
		 * had been processed, skip ahead to commit, and iterate
		 * without splicing in more incoming requests from upper layers.
		 *
		 * Else, if all incoming have been processed, they have become
		 * "pending" (to be submitted after next transaction commit).
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

static bool request_size_bad(struct drbd_device *device, struct bio *bio)
{
	unsigned int size = bio->bi_iter.bi_size;
	if (!expect(device, size <= DRBD_MAX_BATCH_BIO_SIZE && IS_ALIGNED(size, SECTOR_SIZE)))
		return true;
	return false;
}

/* drbd_submit_bio() - entry point for data into DRBD
 *
 * Request handling flow:
 *
 *                                    drbd_submit_bio
 *                                           |
 *                                           v          wait for AL
 * do_retry -----------------------> __drbd_make_request --------> drbd_queue_write
 *     ^                                     |                          |
 *     |                                     |                         ...
 *     |                                     |                          |
 *     |                                     |                          v    AL extent active
 *     |     drbd_do_submit_conflict --------+                     do_submit ----------------+
 *     |                ^                    |                          |                    |
 *    ...               |                    |                          v                    v
 *     |               ...                   |               send_and_submit_pending   submit_fast_path
 *     |                |                    v                          |                    |
 *     |                +----------- drbd_conflict_submit_write <-------+--------------------+
 *     |                  conflict           |
 *     |                                     v
 * drbd_restart_request <----------- drbd_send_and_submit
 *                      RQ_POSTPONED         |
 *                                           v
 *                                   Request state machine
 */
void drbd_submit_bio(struct bio *bio)
{
	struct drbd_device *device = bio->bi_bdev->bd_disk->private_data;
#ifdef CONFIG_DRBD_TIMING_STATS
	ktime_t start_kt;
#endif
	unsigned long start_jif;

	if (drbd_fail_request_early(device, bio)) {
		bio->bi_status = BLK_STS_IOERR;
		bio_endio(bio);
		return;
	}

	bio = bio_split_to_limits(bio);
	if (!bio)
		return;

	if (device->cached_err_io || request_size_bad(device, bio)) {
		bio->bi_status = BLK_STS_IOERR;
		bio_endio(bio);
		return;
	}

	/* This is both an optimization: READ of size 0, nothing to do
	 * and a workaround: (older) ZFS explodes on size zero reads, see
	 * https://github.com/zfsonlinux/zfs/issues/8379
	 * Actually don't do anything for size zero bios.
	 * Add a "WARN_ONCE", so we can tell the caller to stop doing this.
	 */
	if (bio_op(bio) == REQ_OP_READ && bio->bi_iter.bi_size == 0) {
		WARN_ONCE(1, "size zero read from upper layers");
		bio_endio(bio);
		return;
	}

	ktime_get_accounting(start_kt);
	start_jif = jiffies;

	__drbd_make_request(device, bio, start_kt, start_jif);
}

static unsigned long time_min_in_future(unsigned long now,
		unsigned long t1, unsigned long t2)
{
	bool t1_in_future = time_after(t1, now);
	bool t2_in_future = time_after(t2, now);

	/* Ensure that we never return a time in the past. */
	t1 = t1_in_future ? t1 : now;
	t2 = t2_in_future ? t2 : now;

	if (!t1_in_future)
		return t2;

	if (!t2_in_future)
		return t1;

	return time_after(t1, t2) ? t2 : t1;
}

static bool net_timeout_reached(struct drbd_request *net_req,
		struct drbd_peer_device *peer_device,
		unsigned long now, unsigned long ent,
		unsigned int ko_count, unsigned int timeout)
{
	struct drbd_connection *connection = peer_device->connection;
	int peer_node_id = peer_device->node_id;
	unsigned long pre_send_jif = net_req->pre_send_jif[peer_node_id];

	if (!time_after(now, pre_send_jif + ent))
		return false;

	if (time_in_range(now, connection->last_reconnect_jif, connection->last_reconnect_jif + ent))
		return false;

	if (net_req->net_rq_state[peer_node_id] & RQ_NET_PENDING) {
		drbd_warn(peer_device, "Remote failed to finish a request within %ums > ko-count (%u) * timeout (%u * 0.1s)\n",
			jiffies_to_msecs(now - pre_send_jif), ko_count, timeout);
		return true;
	}

	/* We received an ACK already (or are using protocol A),
	 * but are waiting for the epoch closing barrier ack.
	 * Check if we sent the barrier already.  We should not blame the peer
	 * for being unresponsive, if we did not even ask it yet. */
	if (net_req->epoch == connection->send.current_epoch_nr) {
		/* It is OK for the barrier to be delayed for a long time for a
		 * suspended request. */
		if (!(net_req->local_rq_state & RQ_COMPLETION_SUSP))
			drbd_warn(peer_device,
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
		drbd_warn(peer_device, "Remote failed to answer a P_BARRIER (sent at %lu jif; now=%lu jif) within %ums > ko-count (%u) * timeout (%u * 0.1s)\n",
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
	struct drbd_resource *resource = device->resource;
	struct drbd_connection *connection;
	struct drbd_request *req_read, *req_write;
	unsigned long oldest_submit_jif, irq_flags;
	unsigned long disk_timeout = 0, effective_timeout = 0, now = jiffies, next_trigger_time = now;
	bool restart_timer = false, io_error = false;
	unsigned long timeout_peers = 0;
	int node_id;

	rcu_read_lock();
	if (get_ldev(device)) { /* implicit state.disk >= D_INCONSISTENT */
		disk_timeout = rcu_dereference(device->ldev->disk_conf)->disk_timeout * HZ / 10;
		put_ldev(device);
	}
	rcu_read_unlock();

	/* FIXME right now, this basically does a full transfer log walk *every time* */
	read_lock_irq(&resource->state_rwlock);
	if (disk_timeout) {
		unsigned long write_pre_submit_jif = 0, read_pre_submit_jif = 0;

		spin_lock(&device->pending_completion_lock); /* local irq already disabled */
		req_read = list_first_entry_or_null(&device->pending_completion[0], struct drbd_request, req_pending_local);
		req_write = list_first_entry_or_null(&device->pending_completion[1], struct drbd_request, req_pending_local);
		spin_unlock(&device->pending_completion_lock);

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
			effective_timeout = min_not_zero(effective_timeout, disk_timeout);
			next_trigger_time = time_min_in_future(now,
					next_trigger_time, oldest_submit_jif + disk_timeout);
			restart_timer = true;
		}

		if (time_after(now, oldest_submit_jif + disk_timeout) &&
		    !time_in_range(now, device->last_reattach_jif, device->last_reattach_jif + disk_timeout))
			io_error = true;
	}
	for_each_connection(connection, resource) {
		struct drbd_peer_device *peer_device = conn_peer_device(connection, device->vnr);
		struct net_conf *nc;
		struct drbd_request *req;
		unsigned long effective_net_timeout = 0;
		unsigned long pre_send_jif = now;
		unsigned int ko_count = 0, timeout = 0;

		rcu_read_lock();
		nc = rcu_dereference(connection->transport.net_conf);
		if (nc) {
			/* effective timeout = ko_count * timeout */
			if (connection->cstate[NOW] == C_CONNECTED) {
				ko_count = nc->ko_count;
				timeout = nc->timeout;
				effective_net_timeout = timeout * HZ/10 * ko_count;
			}
		}
		rcu_read_unlock();

		/* This connection is not established,
		 * or has the effective timeout disabled.
		 * no timer restart needed (for this connection). */
		if (!effective_net_timeout)
			continue;

		/* maybe the oldest request waiting for the peer is in fact still
		 * blocking in tcp sendmsg.  That's ok, though, that's handled via the
		 * socket send timeout, requesting a ping, and bumping ko-count in
		 * we_should_drop_the_connection().
		 */

		/* check the oldest request we did successfully sent,
		 * but which is still waiting for an ACK. */
		req = connection->req_ack_pending;

		/* If we don't have such request (e.g. protocol A)
		 * check the oldest request which is still waiting on its epoch
		 * closing barrier ack. */
		if (!req) {
			req = connection->req_not_net_done;

			/* If we did not send the request yet then pre_send_jif
			 * is not set. Treat this the same as when there are no
			 * requests pending. */
			if (req && !(req->net_rq_state[connection->peer_node_id] & RQ_NET_SENT))
				req = NULL;
		}

		if (req)
			pre_send_jif = req->pre_send_jif[connection->peer_node_id];

		effective_timeout = min_not_zero(effective_timeout, effective_net_timeout);
		next_trigger_time = time_min_in_future(now,
				next_trigger_time, pre_send_jif + effective_net_timeout);
		/* Restart the timer, even if there are no pending requests at all.
		 * We currently do not re-arm from the submit path. */
		restart_timer = true;

		/* We have one timer per "device",
		 * but the "oldest" request is per "connection".
		 * Evaluate the oldest peer request only in one timer! */
		if (req == NULL || req->device != device)
			continue;

		if (net_timeout_reached(req, peer_device, now, effective_net_timeout, ko_count, timeout)) {
			dynamic_drbd_dbg(peer_device, "Request at %llus+%u timed out\n",
					(unsigned long long) req->i.sector,
					req->i.size);
			timeout_peers |= NODE_MASK(connection->peer_node_id);
		}
	}
	read_unlock_irq(&resource->state_rwlock);

	if (io_error) {
		drbd_warn(device, "Local backing device failed to meet the disk-timeout\n");
		drbd_handle_io_error(device, DRBD_FORCE_DETACH);
	}

	BUILD_BUG_ON(sizeof(timeout_peers) * 8 < DRBD_NODE_ID_MAX);
	for_each_set_bit(node_id, &timeout_peers, DRBD_NODE_ID_MAX) {
		connection = drbd_get_connection_by_node_id(resource, node_id);
		if (!connection)
			continue;
		begin_state_change(resource, &irq_flags, CS_VERBOSE | CS_HARD);
		__change_cstate(connection, C_TIMEOUT);
		end_state_change(resource, &irq_flags);
		kref_put(&connection->kref, drbd_destroy_connection);
	}

	if (restart_timer) {
		next_trigger_time = time_min_in_future(now, next_trigger_time, now + effective_timeout);
		mod_timer(&device->request_timer, next_trigger_time);
	}
}

/**
 * drbd_handle_io_error_: Handle the on_io_error setting, should be called from all io completion handlers
 * @device: DRBD device.
 * @df:     Detach flags indicating the kind of IO that failed.
 * @where:  Calling function name.
 */
void drbd_handle_io_error_(struct drbd_device *device,
	enum drbd_force_detach_flags df, const char *where)
{
	unsigned long flags;
	enum drbd_io_error_p ep;

	write_lock_irqsave(&device->resource->state_rwlock, flags);

	rcu_read_lock();
	ep = rcu_dereference(device->ldev->disk_conf)->on_io_error;
	rcu_read_unlock();
	switch (ep) {
	case EP_PASS_ON: /* FIXME would this be better named "Ignore"? */
		if (df == DRBD_READ_ERROR ||  df == DRBD_WRITE_ERROR) {
			if (drbd_ratelimit())
				drbd_err(device, "Local IO failed in %s.\n", where);
			if (device->disk_state[NOW] > D_INCONSISTENT) {
				begin_state_change_locked(device->resource, CS_HARD);
				__change_disk_state(device, D_INCONSISTENT);
				end_state_change_locked(device->resource);
			}
			break;
		}
		fallthrough;	/* for DRBD_META_IO_ERROR or DRBD_FORCE_DETACH */
	case EP_DETACH:
	case EP_CALL_HELPER:
		/* Force-detach is not really an IO error, but rather a
		 * desperate measure to try to deal with a completely
		 * unresponsive lower level IO stack.
		 * Still it should be treated as a WRITE error.
		 */
		if (df == DRBD_FORCE_DETACH)
			set_bit(FORCE_DETACH, &device->flags);
		if (device->disk_state[NOW] > D_FAILED) {
			begin_state_change_locked(device->resource, CS_HARD);
			__change_disk_state(device, D_FAILED);
			end_state_change_locked(device->resource);
			drbd_err(device,
				"Local IO failed in %s. Detaching...\n", where);
		}
		break;
	}

	write_unlock_irqrestore(&device->resource->state_rwlock, flags);
}
