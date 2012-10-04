/*
   drbd_req.c

   This file is part of DRBD by Philipp Reisner and Lars Ellenberg.

   Copyright (C) 2001-2008, LINBIT Information Technologies GmbH.
   Copyright (C) 1999-2008, Philipp Reisner <philipp.reisner@linbit.com>.
   Copyright (C) 2002-2008, Lars Ellenberg <lars.ellenberg@linbit.com>.

   drbd is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   drbd is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with drbd; see the file COPYING.  If not, write to
   the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.

 */

#include <linux/module.h>

#include <linux/slab.h>
#include <linux/drbd.h>
#include "drbd_int.h"
#include "drbd_req.h"


/* We only support diskstats for 2.6.16 and up.
 * see also commit commit a362357b6cd62643d4dda3b152639303d78473da
 * Author: Jens Axboe <axboe@suse.de>
 * Date:   Tue Nov 1 09:26:16 2005 +0100
 *     [BLOCK] Unify the separate read/write io stat fields into arrays */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,16)
#define _drbd_start_io_acct(...) do {} while (0)
#define _drbd_end_io_acct(...)   do {} while (0)
#else

STATIC bool drbd_may_do_local_read(struct drbd_device *device, sector_t sector, int size);

/* Update disk stats at start of I/O request */
static void _drbd_start_io_acct(struct drbd_device *device, struct drbd_request *req, struct bio *bio)
{
	const int rw = bio_data_dir(bio);
#ifndef __disk_stat_inc
	int cpu;
#endif

#ifdef __disk_stat_inc
	__disk_stat_inc(device->vdisk, ios[rw]);
	__disk_stat_add(device->vdisk, sectors[rw], bio_sectors(bio));
	disk_round_stats(device->vdisk);
	device->vdisk->in_flight++;
#else
	cpu = part_stat_lock();
	part_round_stats(cpu, &device->vdisk->part0);
	part_stat_inc(cpu, &device->vdisk->part0, ios[rw]);
	part_stat_add(cpu, &device->vdisk->part0, sectors[rw], bio_sectors(bio));
	(void) cpu; /* The macro invocations above want the cpu argument, I do not like
		       the compiler warning about cpu only assigned but never used... */
	part_inc_in_flight(&device->vdisk->part0, rw);
	part_stat_unlock();
#endif
}

/* Update disk stats when completing request upwards */
static void _drbd_end_io_acct(struct drbd_device *device, struct drbd_request *req)
{
	int rw = bio_data_dir(req->master_bio);
	unsigned long duration = jiffies - req->start_time;
#ifndef __disk_stat_inc
	int cpu;
#endif

#ifdef __disk_stat_add
	__disk_stat_add(device->vdisk, ticks[rw], duration);
	disk_round_stats(device->vdisk);
	device->vdisk->in_flight--;
#else
	cpu = part_stat_lock();
	part_stat_add(cpu, &device->vdisk->part0, ticks[rw], duration);
	part_round_stats(cpu, &device->vdisk->part0);
	part_dec_in_flight(&device->vdisk->part0, rw);
	part_stat_unlock();
#endif
}

#endif

static struct drbd_request *drbd_req_new(struct drbd_device *device,
					       struct bio *bio_src)
{
	struct drbd_request *req;
	int i;

	req = mempool_alloc(drbd_request_mempool, GFP_NOIO | __GFP_ZERO);
	if (!req)
		return NULL;

	drbd_req_make_private_bio(req, bio_src);
	req->device      = device;
	req->master_bio  = bio_src;
	req->epoch       = 0;

	drbd_clear_interval(&req->i);
	req->i.sector     = bio_src->bi_sector;
	req->i.size      = bio_src->bi_size;
	req->i.local = true;
	req->i.waiting = false;

	INIT_LIST_HEAD(&req->tl_requests);

	/* one reference to be put by __drbd_make_request */
	atomic_set(&req->completion_ref, 1);
	/* one kref as long as completion_ref > 0 */
	kref_init(&req->kref);

	for (i = 0; i <= device->bitmap->bm_max_peers; i++)
		req->rq_state[i] = 0;
	if (bio_data_dir(bio_src) == WRITE)
		req->rq_state[0] |= RQ_WRITE;

	return req;
}

void drbd_req_destroy(struct kref *kref)
{
	struct drbd_request *req = container_of(kref, struct drbd_request, kref);
	struct drbd_device *device;
	struct drbd_peer_device *peer_device;
	unsigned int req_size, s;

tail_recursion:
	device = req->device;
	s = req->rq_state[0];
	req_size = req->i.size;

	/* paranoia */
	rcu_read_lock();
	for_each_peer_device(peer_device, device) {
		unsigned ns = drbd_req_state_by_peer_device(req, peer_device);
		if (!(ns & RQ_NET_MASK))
			continue;
		if (ns & RQ_NET_DONE)
			continue;

		drbd_err(device,
			"drbd_req_destroy: Logic BUG rq_state: (0:%x, %d:%x), completion_ref = %d\n",
			s, 1 + peer_device->bitmap_index, ns, atomic_read(&req->completion_ref));
		rcu_read_unlock();
		return;
	}
	rcu_read_unlock();

	/* more paranoia */
	if ((req->master_bio && !(s & RQ_POSTPONED)) ||
		atomic_read(&req->completion_ref) || (s & RQ_LOCAL_PENDING)) {
		drbd_err(device, "drbd_req_destroy: Logic BUG rq_state: %x, completion_ref = %d\n",
				s, atomic_read(&req->completion_ref));
		return;
	}

	/* remove it from the transfer log.
	 * well, only if it had been there in the first
	 * place... if it had not (local only or conflicting
	 * and never sent), it should still be "empty" as
	 * initialized in drbd_req_new(), so we can list_del() it
	 * here unconditionally */
	list_del_init(&req->tl_requests);

	if (s & RQ_WRITE) {
		/* There is a special case:
		 * we may notice late that IO was suspended,
		 * and postpone, or schedule for retry, a write,
		 * before it even was submitted or sent.
		 * In that case we do not want to touch the bitmap at all.
		 */
		if ((s & (RQ_POSTPONED|RQ_LOCAL_MASK|RQ_NET_MASK)) != RQ_POSTPONED) {
			unsigned long bits = -1, mask = -1;
			int bm_max_peers = 0, bitmap_index;

			if ((s & RQ_LOCAL_OK) && get_ldev(device)) {
				bm_max_peers = device->bitmap->bm_max_peers;
				put_ldev(device);
			}
			for (bitmap_index = 0; bitmap_index < bm_max_peers; bitmap_index++) {
				unsigned int rq_state;

				rq_state = req->rq_state[1 + bitmap_index];
				if (rq_state & RQ_NET_OK) {
					if (rq_state & RQ_NET_SIS)
						clear_bit(bitmap_index, &bits);
					else
						clear_bit(bitmap_index, &mask);
				}
			}
			drbd_set_sync(device, req->i.sector, req->i.size, bits, mask);
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
			if (get_ldev_if_state(device, D_FAILED)) {
				drbd_al_complete_io(device, &req->i);
				put_ldev(device);
			} else if (drbd_ratelimit()) {
				drbd_warn(device, "Should have called drbd_al_complete_io(, %llu, %u), "
					  "but my Disk seems to have failed :(\n",
					  (unsigned long long) req->i.sector, req->i.size);

			}
		}
	}

	mempool_free(req, drbd_request_mempool);

	if (s & RQ_WRITE && req_size) {
		list_for_each_entry(req, &device->resource->transfer_log, tl_requests) {
			if (req->rq_state[0] & RQ_WRITE) {
				/*
				 * Do the equivalent of:
				 *   kref_put(&req->kref, drbd_req_destroy)
				 * without recursing into the destructor.
				 */
				if (atomic_dec_and_test(&req->kref.refcount))
					goto tail_recursion;
				break;
			}
		}
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
static void start_new_tl_epoch(struct drbd_resource *resource)
{
	/* no point closing an epoch, if it is empty, anyways. */
	if (resource->current_tle_writes == 0)
		return;

	resource->current_tle_writes = 0;
	atomic_inc(&resource->current_tle_nr);
	wake_all_senders(resource);
}

void complete_master_bio(struct drbd_device *device,
		struct bio_and_error *m)
{
	bio_endio(m->bio, m->error);
	dec_ap_bio(device);
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

/* Helper for __req_mod().
 * Set m->bio to the master bio, if it is fit to be completed,
 * or leave it alone (it is initialized to NULL in __req_mod),
 * if it has already been completed, or cannot be completed yet.
 * If m->bio is set, the error status to be returned is placed in m->error.
 */
static
void drbd_req_complete(struct drbd_request *req, struct bio_and_error *m)
{
	const unsigned s = req->rq_state[0];
	struct drbd_device *device = req->device;
	struct drbd_peer_device *peer_device;
	int rw;
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

	rcu_read_lock();
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
			s, 1 + peer_device->bitmap_index, ns, atomic_read(&req->completion_ref));
		rcu_read_unlock();
		return;
	}
	rcu_read_unlock();

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

	rw = bio_rw(req->master_bio);

	/* remove the request from the conflict detection
	 * respective block_id verification hash */
	if (!drbd_interval_empty(&req->i)) {
		struct rb_root *root;

		if (rw == WRITE)
			root = &device->write_requests;
		else
			root = &device->read_requests;
		drbd_remove_request_interval(root, req);
	}
	/*
	     FIXME either drop this paranoia,
	     or calculate it in for_each_peer_device above.
	     else if (!(s & RQ_POSTPONED))
		D_ASSERT(device, (s & (RQ_NET_MASK & ~RQ_NET_DONE)) == 0);
	 */

	/* Before we can signal completion to the upper layers,
	 * we may need to close the current transfer log epoch.
	 * We are within the request lock, so we can simply compare
	 * the request epoch number with the current transfer log
	 * epoch number.  If they match, increase the current_tle_nr,
	 * and reset the transfer log epoch write_cnt.
	 */
	if (rw == WRITE &&
	    req->epoch == atomic_read(&device->resource->current_tle_nr))
		start_new_tl_epoch(device->resource);

	/* Update disk stats */
	_drbd_end_io_acct(device, req);

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
	 * READA may fail, and will not be retried.
	 *
	 * WRITE should have used all available paths already.
	 */
	if (!ok && rw == READ && !list_empty(&req->tl_requests))
		req->rq_state[0] |= RQ_POSTPONED;

	if (!(req->rq_state[0] & RQ_POSTPONED)) {
		m->error = ok ? 0 : (error ?: -EIO);
		m->bio = req->master_bio;
		req->master_bio = NULL;
	}
}

static int drbd_req_put_completion_ref(struct drbd_request *req, struct bio_and_error *m, int put)
{
	D_ASSERT(req->device, m || (req->rq_state[0] & RQ_POSTPONED));

	if (!atomic_sub_and_test(put, &req->completion_ref))
		return 0;

	drbd_req_complete(req, m);

	if (req->rq_state[0] & RQ_POSTPONED) {
		/* don't destroy the req object just yet,
		 * but queue it for retry */
		drbd_restart_request(req);
		return 0;
	}

	return 1;
}

/* I'd like this to be the only place that manipulates
 * req->completion_ref and req->kref. */
static void mod_rq_state(struct drbd_request *req, struct bio_and_error *m,
		struct drbd_peer_device *peer_device,
		int clear, int set)
{
	unsigned old_net;
	unsigned old_local = req->rq_state[0];
	unsigned set_local = set & RQ_STATE_0_MASK;
	unsigned clear_local = clear & RQ_STATE_0_MASK;
	int c_put = 0;
	int k_put = 0;
	const int idx = peer_device ?  1 + peer_device->bitmap_index : 0;

	/* FIXME n_connections, when this request was created/scheduled. */
	BUG_ON(idx > MAX_PEERS);
	BUG_ON(idx < 0);

	old_net = req->rq_state[idx];

	set &= ~RQ_STATE_0_MASK;
	clear &= ~RQ_STATE_0_MASK;

	if (!idx) {
		/* do not try to manipulate net state bits
		 * without an associated state slot! */
		BUG_ON(set);
		BUG_ON(clear);
	}

	if (drbd_suspended(req->device) && !((old_local | clear_local) & RQ_COMPLETION_SUSP))
		set_local |= RQ_COMPLETION_SUSP;

	/* apply */

	req->rq_state[0] &= ~clear_local;
	req->rq_state[0] |= set_local;

	req->rq_state[idx] &= ~clear;
	req->rq_state[idx] |= set;


	/* no change? */
	if (req->rq_state[0] == old_local && req->rq_state[idx] == old_net)
		return;

	/* intent: get references */

	if (!(old_local & RQ_LOCAL_PENDING) && (set_local & RQ_LOCAL_PENDING))
		atomic_inc(&req->completion_ref);

	if (!(old_net & RQ_NET_PENDING) && (set & RQ_NET_PENDING)) {
		inc_ap_pending(peer_device);
		atomic_inc(&req->completion_ref);
	}

	if (!(old_net & RQ_NET_QUEUED) && (set & RQ_NET_QUEUED))
		atomic_inc(&req->completion_ref);

	if (!(old_net & RQ_EXP_BARR_ACK) && (set & RQ_EXP_BARR_ACK))
		kref_get(&req->kref); /* wait for the DONE */

	if (!(old_net & RQ_NET_SENT) && (set & RQ_NET_SENT))
		atomic_add(req->i.size >> 9, &req->device->ap_in_flight);

	if (!(old_local & RQ_COMPLETION_SUSP) && (set_local & RQ_COMPLETION_SUSP))
		atomic_inc(&req->completion_ref);

	/* progress: put references */

	if ((old_local & RQ_COMPLETION_SUSP) && (clear_local & RQ_COMPLETION_SUSP))
		++c_put;

	if (!(old_local & RQ_LOCAL_ABORTED) && (set_local & RQ_LOCAL_ABORTED)) {
		D_ASSERT(req->device, req->rq_state[0] & RQ_LOCAL_PENDING);
		/* local completion may still come in later,
		 * we need to keep the req object around. */
		kref_get(&req->kref);
		++c_put;
	}

	if ((old_local & RQ_LOCAL_PENDING) && (clear_local & RQ_LOCAL_PENDING)) {
		if (req->rq_state[0] & RQ_LOCAL_ABORTED)
			++k_put;
		else
			++c_put;
	}

	if ((old_net & RQ_NET_PENDING) && (clear & RQ_NET_PENDING)) {
		dec_ap_pending(peer_device);
		++c_put;
	}

	if ((old_net & RQ_NET_QUEUED) && (clear & RQ_NET_QUEUED))
		++c_put;

	if ((old_net & RQ_EXP_BARR_ACK) && !(old_net & RQ_NET_DONE) && (set & RQ_NET_DONE)) {
		if (req->rq_state[idx] & RQ_NET_SENT)
			atomic_sub(req->i.size >> 9, &req->device->ap_in_flight);
		++k_put;
	}

	/* potentially complete and destroy */

	if (k_put || c_put) {
		/* Completion does it's own kref_put.  If we are going to
		 * kref_sub below, we need req to be still around then. */
		int at_least = k_put + !!c_put;
		int refcount = atomic_read(&req->kref.refcount);
		if (refcount < at_least)
			drbd_err(req->device,
				"mod_rq_state: Logic BUG: 0: %x -> %x, %d: %x -> %x: refcount = %d, should be >= %d\n",
				old_local, req->rq_state[0],
				idx, old_net, req->rq_state[idx],
				refcount, at_least);
	}

	/* If we made progress, retry conflicting peer requests, if any. */
	if (req->i.waiting)
		wake_up(&req->device->misc_wait);

	if (c_put)
		k_put += drbd_req_put_completion_ref(req, m, c_put);
	if (k_put)
		kref_sub(&req->kref, k_put, drbd_req_destroy);
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
int __req_mod(struct drbd_request *req, enum drbd_req_event what,
		struct drbd_peer_device *peer_device,
		struct bio_and_error *m)
{
	struct drbd_device *device = req->device;
	struct net_conf *nc;
	int p, rv = 0;
	int idx;

	if (m)
		m->bio = NULL;

	idx = peer_device ? 1 + peer_device->bitmap_index : 0;

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
		D_ASSERT(device, idx && !(req->rq_state[idx] & RQ_NET_MASK));
		rcu_read_lock();
		nc = rcu_dereference(peer_device->connection->net_conf);
		p = nc->wire_protocol;
		rcu_read_unlock();
		req->rq_state[idx] |=
			p == DRBD_PROT_C ? RQ_EXP_WRITE_ACK :
			p == DRBD_PROT_B ? RQ_EXP_RECEIVE_ACK : 0;
		mod_rq_state(req, m, peer_device, 0, RQ_NET_PENDING);
		break;

	case TO_BE_SUBMITTED: /* locally */
		/* reached via __drbd_make_request */
		D_ASSERT(device, !(req->rq_state[0] & RQ_LOCAL_MASK));
		mod_rq_state(req, m, peer_device, 0, RQ_LOCAL_PENDING);
		break;

	case COMPLETED_OK:
		if (req->rq_state[0] & RQ_WRITE)
			device->writ_cnt += req->i.size >> 9;
		else
			device->read_cnt += req->i.size >> 9;

		mod_rq_state(req, m, peer_device, RQ_LOCAL_PENDING,
				RQ_LOCAL_COMPLETED|RQ_LOCAL_OK);
		break;

	case ABORT_DISK_IO:
		mod_rq_state(req, m, peer_device, 0, RQ_LOCAL_ABORTED);
		break;

	case READ_COMPLETED_WITH_ERROR:
		drbd_set_out_of_sync(peer_device, req->i.sector, req->i.size);
		/* fall through. */
	case WRITE_COMPLETED_WITH_ERROR:
		__drbd_chk_io_error(device, DRBD_IO_ERROR);
		/* fall through. */
	case READ_AHEAD_COMPLETED_WITH_ERROR:
		/* it is legal to fail READA, no __drbd_chk_io_error in that case. */
		mod_rq_state(req, m, peer_device, RQ_LOCAL_PENDING, RQ_LOCAL_COMPLETED);
		break;

	case QUEUE_FOR_NET_READ:
		/* READ or READA, and
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

		D_ASSERT(device, req->rq_state[idx] & RQ_NET_PENDING);
		D_ASSERT(device, (req->rq_state[0] & RQ_LOCAL_MASK) == 0);
		mod_rq_state(req, m, peer_device, 0, RQ_NET_QUEUED);
		if (!peer_device->connection->todo.req_next)
			peer_device->connection->todo.req_next = req;
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
		D_ASSERT(device, req->rq_state[idx] & RQ_NET_PENDING);
		mod_rq_state(req, m, peer_device, 0, RQ_NET_QUEUED|RQ_EXP_BARR_ACK);

		/* close the epoch, in case it outgrew the limit */
		rcu_read_lock();
		nc = rcu_dereference(peer_device->connection->net_conf);
		p = nc->max_epoch_size;
		rcu_read_unlock();
		if (device->resource->current_tle_writes >= p)
			start_new_tl_epoch(device->resource);
		if (!peer_device->connection->todo.req_next)
			peer_device->connection->todo.req_next = req;
		break;

	case QUEUE_FOR_SEND_OOS:
		mod_rq_state(req, m, peer_device, 0, RQ_NET_QUEUED);
		if (!peer_device->connection->todo.req_next)
			peer_device->connection->todo.req_next = req;
		break;

	case READ_RETRY_REMOTE_CANCELED:
	case SEND_CANCELED:
	case SEND_FAILED:
		/* real cleanup will be done from tl_clear.  just update flags
		 * so it is no longer marked as on the sender queue */
		mod_rq_state(req, m, peer_device, RQ_NET_QUEUED, 0);
		break;

	case HANDED_OVER_TO_NETWORK:
		/* assert something? */
		if (bio_data_dir(req->master_bio) == WRITE)

		if (bio_data_dir(req->master_bio) == WRITE &&
		    !(req->rq_state[idx] & (RQ_EXP_RECEIVE_ACK | RQ_EXP_WRITE_ACK))) {
			/* this is what is dangerous about protocol A:
			 * pretend it was successfully written on the peer. */
			if (req->rq_state[idx] & RQ_NET_PENDING)
				mod_rq_state(req, m, peer_device, RQ_NET_PENDING, RQ_NET_OK);
			/* else: neg-ack was faster... */
			/* it is still not yet RQ_NET_DONE until the
			 * corresponding epoch barrier got acked as well,
			 * so we know what to dirty on connection loss */
		}
		mod_rq_state(req, m, peer_device, RQ_NET_QUEUED, RQ_NET_SENT);
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
		D_ASSERT(device, req->rq_state[idx] & RQ_NET_PENDING);
		D_ASSERT(device, req->rq_state[idx] & RQ_EXP_WRITE_ACK);
		mod_rq_state(req, m, peer_device, RQ_NET_PENDING, RQ_NET_DONE|RQ_NET_OK);
		break;

	case WRITE_ACKED_BY_PEER_AND_SIS:
		req->rq_state[idx] |= RQ_NET_SIS;
	case WRITE_ACKED_BY_PEER:
		D_ASSERT(device, req->rq_state[idx] & RQ_EXP_WRITE_ACK);
		/* protocol C; successfully written on peer.
		 * Nothing more to do here.
		 * We want to keep the tl in place for all protocols, to cater
		 * for volatile write-back caches on lower level devices. */

		goto ack_common;
	case RECV_ACKED_BY_PEER:
		D_ASSERT(device, req->rq_state[idx] & RQ_EXP_RECEIVE_ACK);
		/* protocol B; pretends to be successfully written on peer.
		 * see also notes above in HANDED_OVER_TO_NETWORK about
		 * protocol != C */
	ack_common:
		D_ASSERT(device, req->rq_state[idx] & RQ_NET_PENDING);
		mod_rq_state(req, m, peer_device, RQ_NET_PENDING, RQ_NET_OK);
		break;

	case POSTPONE_WRITE:
		D_ASSERT(device, req->rq_state[idx] & RQ_EXP_WRITE_ACK);
		/* If this node has already detected the write conflict, the
		 * worker will be waiting on misc_wait.  Wake it up once this
		 * request has completed locally.
		 */
		D_ASSERT(device, req->rq_state[idx] & RQ_NET_PENDING);
		req->rq_state[0] |= RQ_POSTPONED;
		if (req->i.waiting)
			wake_up(&req->device->misc_wait);
		/* Do not clear RQ_NET_PENDING. This request will make further
		 * progress via restart_conflicting_writes() or
		 * fail_postponed_requests(). Hopefully. */
		break;

	case NEG_ACKED:
		mod_rq_state(req, m, peer_device, RQ_NET_OK|RQ_NET_PENDING, 0);
		break;

	case FAIL_FROZEN_DISK_IO:
		if (!(req->rq_state[0] & RQ_LOCAL_COMPLETED))
			break;
		mod_rq_state(req, m, peer_device, RQ_COMPLETION_SUSP, 0);
		break;

	case RESTART_FROZEN_DISK_IO:
#if 0
		/* FIXME; do we need a (temporary) dedicated thread for this? */
		if (!(req->rq_state[0] & RQ_LOCAL_COMPLETED))
			break;

		mod_rq_state(req, m, peer_device,
				RQ_COMPLETION_SUSP|RQ_LOCAL_COMPLETED,
				RQ_LOCAL_PENDING);

		rv = MR_READ;
		if (bio_data_dir(req->master_bio) == WRITE)
			rv = MR_WRITE;

		get_ldev(device); /* always succeeds in this call path */
		req->w.cb = w_restart_disk_io;
		drbd_queue_work(&device->resource->work, &req->w);
		break;
#else
		BUG(); /* FIXME */
		break;
#endif

	case RESEND:
		/* Simply complete (local only) READs. */
		if (!(req->rq_state[0] & RQ_WRITE) && !(req->rq_state[idx] & RQ_NET_MASK)) {
			mod_rq_state(req, m, peer_device, RQ_COMPLETION_SUSP, 0);
			break;
		}

		/* If RQ_NET_OK is already set, we got a P_WRITE_ACK or P_RECV_ACK
		   before the connection loss (B&C only); only P_BARRIER_ACK
		   (or the local completion?) was missing when we suspended.
		   Throwing them out of the TL here by pretending we got a BARRIER_ACK.
		   During connection handshake, we ensure that the peer was not rebooted.

		   Resending is only allowed on synchronous connections,
		   where all requests not yet completed to upper layers whould
		   be in the same "reorder-domain", there can not possibly be
		   any dependency between incomplete requests, and we are
		   allowed to complete this one "out-of-sequence".
		 */
		if (!(req->rq_state[idx] & RQ_NET_OK)) {
			mod_rq_state(req, m, peer_device, RQ_COMPLETION_SUSP,
					RQ_NET_QUEUED|RQ_NET_PENDING);
			break;
		}
		/* else, fall through to BARRIER_ACKED */

	case BARRIER_ACKED:
		/* barrier ack for READ requests does not make sense */
		if (!(req->rq_state[0] & RQ_WRITE))
			break;

		if (req->rq_state[idx] & RQ_NET_PENDING) {
			/* barrier came in before all requests were acked.
			 * this is bad, because if the connection is lost now,
			 * we won't be able to clean them up... */
			drbd_err(device, "FIXME (BARRIER_ACKED but pending)\n");
		}
		/* Allowed to complete requests, even while suspended.
		 * As this is called for all requests within a matching epoch,
		 * we need to filter, and only set RQ_NET_DONE for those that
		 * have actually been on the wire. */
		mod_rq_state(req, m, peer_device, RQ_COMPLETION_SUSP,
				(req->rq_state[idx] & RQ_NET_MASK) ? RQ_NET_DONE : 0);
		break;

	case DATA_RECEIVED:
		D_ASSERT(device, req->rq_state[idx] & RQ_NET_PENDING);
		mod_rq_state(req, m, peer_device, RQ_NET_PENDING, RQ_NET_OK|RQ_NET_DONE);
		break;
	};

	return rv;
}

/* we may do a local read if:
 * - we are consistent (of course),
 * - or we are generally inconsistent,
 *   BUT we are still/already IN SYNC with all peers for this area.
 *   since size may be bigger than BM_BLOCK_SIZE,
 *   we may need to check several bits.
 */
STATIC bool drbd_may_do_local_read(struct drbd_device *device, sector_t sector, int size)
{
	struct drbd_md *md = &device->ldev->md;
	unsigned int bitmap_index;

	unsigned long sbnr, ebnr;
	sector_t esector, nr_sectors;

	if (device->disk_state[NOW] == D_UP_TO_DATE)
		return true;
	if (device->disk_state[NOW] != D_INCONSISTENT)
		return false;
	esector = sector + (size >> 9) - 1;
	nr_sectors = drbd_get_capacity(device->this_bdev);
	D_ASSERT(device, sector  < nr_sectors);
	D_ASSERT(device, esector < nr_sectors);

	sbnr = BM_SECT_TO_BIT(sector);
	ebnr = BM_SECT_TO_BIT(esector);

	for (bitmap_index = 0; bitmap_index < device->bitmap->bm_max_peers; bitmap_index++) {
		struct drbd_md_peer *peer_md = &md->peers[bitmap_index];

		/* Skip bitmap indexes which are not assigned to a peer. */
		if (peer_md->node_id == -1)
			continue;

		if (drbd_bm_count_bits(device, bitmap_index, sbnr, ebnr))
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
		bdi = &device->ldev->backing_bdev->bd_disk->queue->backing_dev_info;
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

	i = drbd_find_overlap(&device->write_requests, sector, size);
	if (!i)
		return;

	for (;;) {
		prepare_to_wait(&device->misc_wait, &wait, TASK_UNINTERRUPTIBLE);
		i = drbd_find_overlap(&device->write_requests, sector, size);
		if (!i)
			break;
		/* Indicate to wake up device->misc_wait on progress.  */
		i->waiting = true;
		spin_unlock_irq(&device->resource->req_lock);
		schedule();
		spin_lock_irq(&device->resource->req_lock);
	}
	finish_wait(&device->misc_wait, &wait);
}

/* called within req_lock and rcu_read_lock() */
static void maybe_pull_ahead(struct drbd_peer_device *peer_device)
{
	struct drbd_connection *connection = peer_device->connection;
	struct drbd_device *device = peer_device->device;
	struct net_conf *nc;
	bool congested = false;
	enum drbd_on_congestion on_congestion;

	nc = rcu_dereference(connection->net_conf);
	on_congestion = nc ? nc->on_congestion : OC_BLOCK;
	if (on_congestion == OC_BLOCK ||
	    connection->agreed_pro_version < 96)
		return;

	/* If I don't even have good local storage, we can not reasonably try
	 * to pull ahead of the peer. We also need the local reference to make
	 * sure mdev->act_log is there.
	 */
	if (!get_ldev_if_state(device, D_UP_TO_DATE))
		return;

	if (nc->cong_fill &&
	    atomic_read(&device->ap_in_flight) >= nc->cong_fill) {
		drbd_info(device, "Congestion-fill threshold reached\n");
		congested = true;
	}

	if (device->act_log->used >= nc->cong_extents) {
		drbd_info(device, "Congestion-extents threshold reached\n");
		congested = true;
	}

	if (congested) {
		/* start a new epoch for non-mirrored writes */
		start_new_tl_epoch(device->resource);

		if (on_congestion == OC_PULL_AHEAD)
			change_repl_state(peer_device, L_AHEAD, 0);
		else			/* on_congestion == OC_DISCONNECT */
			change_cstate(peer_device->connection, C_DISCONNECTING, 0);
	}
	put_ldev(device);
}

static bool drbd_should_do_remote(struct drbd_peer_device *peer_device)
{
	enum drbd_disk_state peer_disk_state = peer_device->disk_state[NOW];

	return peer_disk_state == D_UP_TO_DATE ||
		(peer_disk_state == D_INCONSISTENT &&
		 peer_device->repl_state[NOW] >= L_WF_BITMAP_T &&
		 peer_device->repl_state[NOW] < L_AHEAD);
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

/* If this returns NULL, and req->private_bio is still set,
 * this should be submitted locally.
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
	enum drbd_read_balancing rbm;

	if (req->private_bio) {
		if (!drbd_may_do_local_read(device,
					req->i.sector, req->i.size)) {
			bio_put(req->private_bio);
			req->private_bio = NULL;
			put_ldev(device);
		}
	}
	/* TODO: improve read balancing decisions, take into account drbd
	 * protocol, all peers, pending requests etc. */

	rcu_read_lock();
	rbm = rcu_dereference(device->ldev->disk_conf)->read_balancing;
	if (rbm == RB_PREFER_LOCAL && req->private_bio) {
		rcu_read_unlock();
		return NULL; /* submit locally */
	}
	for_each_peer_device(peer_device, device) {
		if (peer_device->disk_state[NOW] != D_UP_TO_DATE)
			continue;
		if (req->private_bio == NULL ||
		    remote_due_to_read_balancing(device, peer_device,
						 req->i.sector, rbm)) {
			rcu_read_unlock();
			return peer_device;
		}
	}
	rcu_read_unlock();

	return NULL;
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

	/* Need to replicate writes.  Unless it is an empty flush,
	 * which is better mapped to a DRBD P_BARRIER packet,
	 * also for drbd wire protocol compatibility reasons.
	 * If this was a flush, just start a new epoch.
	 * Unless the current epoch was empty anyways, or we are not currently
	 * replicating, in which case there is no point. */
	if (unlikely(req->i.size == 0)) {
		/* The only size==0 bios we expect are empty flushes. */
		D_ASSERT(device, req->master_bio->bi_rw & DRBD_REQ_FLUSH);
		start_new_tl_epoch(device->resource);
		return 0;
	}

	rcu_read_lock();
	for_each_peer_device(peer_device, device) {
		remote = drbd_should_do_remote(peer_device);
		if (remote) {
			maybe_pull_ahead(peer_device);
			remote = drbd_should_do_remote(peer_device);
		}
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
		} else if (drbd_set_out_of_sync(peer_device, req->i.sector, req->i.size))
			_req_mod(req, QUEUE_FOR_SEND_OOS, peer_device);
	}
	rcu_read_unlock();

	return count;
}

static void
drbd_submit_req_private_bio(struct drbd_request *req)
{
	struct drbd_device *device = req->device;
	struct bio *bio = req->private_bio;
	const int rw = bio_rw(bio);

	bio->bi_bdev = device->ldev->backing_bdev;

	/* State may have changed since we grabbed our reference on the
	 * device->ldev member. Double check, and short-circuit to endio.
	 * In case the last activity log transaction failed to get on
	 * stable storage, and this is a WRITE, we may not even submit
	 * this bio. */
	if (get_ldev(device)) {
		if (drbd_insert_fault(device,
				      rw == WRITE ? DRBD_FAULT_DT_WR
				    : rw == READ  ? DRBD_FAULT_DT_RD
				    :               DRBD_FAULT_DT_RA))
			bio_endio(bio, -EIO);
		else
			generic_make_request(bio);
		put_ldev(device);
	} else
		bio_endio(bio, -EIO);
}

void __drbd_make_request(struct drbd_device *device, struct bio *bio, unsigned long start_time)
{
	struct drbd_resource *resource = device->resource;
	const int rw = bio_rw(bio);
	struct bio_and_error m = { NULL, };
	struct drbd_request *req;
	struct drbd_peer_device *peer_device = NULL; /* for read */
	bool no_remote = false;

	/* allocate outside of all locks; */
	req = drbd_req_new(device, bio);
	if (!req) {
		dec_ap_bio(device);
		/* only pass the error to the upper layers.
		 * if user cannot handle io errors, that's not our business. */
		drbd_err(device, "could not kmalloc() req\n");
		bio_endio(bio, -ENOMEM);
		return;
	}
	req->start_time = start_time;

	if (!get_ldev(device)) {
		bio_put(req->private_bio);
		req->private_bio = NULL;
	}

	/* For WRITES going to the local disk, grab a reference on the target
	 * extent.  This waits for any resync activity in the corresponding
	 * resync extent to finish, and, if necessary, pulls in the target
	 * extent into the activity log, which involves further disk io because
	 * of transactional on-disk meta data updates.
	 * Empty flushes don't need to go into the activity log, they can only
	 * flush data for pending writes which are already in there. */
	if (rw == WRITE && req->private_bio && req->i.size
	&& !test_bit(AL_SUSPENDED, &device->flags)) {
		req->rq_state[0] |= RQ_IN_ACT_LOG;
		drbd_al_begin_io(device, &req->i, true);
	}

	spin_lock_irq(&resource->req_lock);
	if (rw == WRITE) {
		/* This may temporarily give up the req_lock,
		 * but will re-aquire it before it returns here.
		 * Needs to be before the check on drbd_suspended() */
		complete_conflicting_writes(req);
	}

	/* no more giving up req_lock from now on! */

	if (drbd_suspended(device)) {
		/* push back and retry: */
		req->rq_state[0] |= RQ_POSTPONED;
		if (req->private_bio) {
			bio_put(req->private_bio);
			req->private_bio = NULL;
			put_ldev(device);
		}
		goto out;
	}

	/* Update disk stats */
	_drbd_start_io_acct(device, req, bio);

	/* We fail READ/READA early, if we can not serve it.
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
		resource->dagtag_sector += bio_sectors(bio);
	req->dagtag_sector = resource->dagtag_sector;
	/* no point in adding empty flushes to the transfer log,
	 * they are mapped to drbd barriers already. */
	if (likely(req->i.size != 0)) {
		if (rw == WRITE) {
			struct drbd_request *req2;

			resource->current_tle_writes++;
			list_for_each_entry_reverse(req2, &resource->transfer_log, tl_requests) {
				if (req2->rq_state[0] & RQ_WRITE) {
					/* Make the new write request depend on
					 * the previous one. */
					kref_get(&req->kref);
					break;
				}
			}
		}
		list_add_tail(&req->tl_requests, &resource->transfer_log);
	}

	if (rw == WRITE) {
		if (!drbd_process_write_request(req))
			no_remote = true;
		else
			wake_all_senders(resource);
	} else {
		if (peer_device) {
			_req_mod(req, TO_BE_SENT, peer_device);
			_req_mod(req, QUEUE_FOR_NET_READ, peer_device);
			wake_up(&peer_device->connection->sender_work.q_wait);
		} else
			no_remote = true;
	}

	if (req->private_bio) {
		/* needs to be marked within the same spinlock */
		_req_mod(req, TO_BE_SUBMITTED, NULL);
		/* but we need to give up the spinlock to submit */
		spin_unlock_irq(&resource->req_lock);
		drbd_submit_req_private_bio(req);
		spin_lock_irq(&resource->req_lock);
	} else if (no_remote) {
nodata:
		if (drbd_ratelimit())
			drbd_err(req->device, "IO ERROR: neither local nor remote disk\n");
		/* A write may have been queued for send_oos, however.
		 * So we can not simply free it, we must go through drbd_req_put_completion_ref() */
	}

out:
	if (drbd_req_put_completion_ref(req, &m, 1))
		kref_put(&req->kref, drbd_req_destroy);
	spin_unlock_irq(&resource->req_lock);

	/* we need to plug ALWAYS since we possibly need to kick lo_dev.
	 * we plug after submit, so we won't miss an unplug event */
	drbd_plug_device(device);

	if (m.bio)
		complete_master_bio(device, &m);
	return;
}

MAKE_REQUEST_TYPE drbd_make_request(struct request_queue *q, struct bio *bio)
{
	struct drbd_device *device = (struct drbd_device *) q->queuedata;
	unsigned long start_time;

	/* We never supported BIO_RW_BARRIER.
	 * We don't need to, anymore, either: starting with kernel 2.6.36,
	 * we have REQ_FUA and REQ_FLUSH, which will be handled transparently
	 * by the block layer. */
	if (unlikely(bio->bi_rw & DRBD_REQ_HARDBARRIER)) {
		bio_endio(bio, -EOPNOTSUPP);
		MAKE_REQUEST_RETURN;
	}

	start_time = jiffies;

	/*
	 * what we "blindly" assume:
	 */
	D_ASSERT(device, IS_ALIGNED(bio->bi_size, 512));

	inc_ap_bio(device);
	__drbd_make_request(device, bio, start_time);
	MAKE_REQUEST_RETURN;
}

/* This is called by bio_add_page().
 *
 * q->max_hw_sectors and other global limits are already enforced there.
 *
 * We need to call down to our lower level device,
 * in case it has special restrictions.
 *
 * We also may need to enforce configured max-bio-bvecs limits.
 *
 * As long as the BIO is empty we have to allow at least one bvec,
 * regardless of size and offset, so no need to ask lower levels.
 */
int drbd_merge_bvec(struct request_queue *q,
#ifdef HAVE_bvec_merge_data
		struct bvec_merge_data *bvm,
#else
		struct bio *bvm,
#endif
		struct bio_vec *bvec)
{
	struct drbd_device *device = (struct drbd_device *) q->queuedata;
	unsigned int bio_size = bvm->bi_size;
	int limit = DRBD_MAX_BIO_SIZE;
	int backing_limit;

	if (bio_size && get_ldev(device)) {
		struct request_queue * const b =
			device->ldev->backing_bdev->bd_disk->queue;
		if (b->merge_bvec_fn) {
			backing_limit = b->merge_bvec_fn(b, bvm, bvec);
			limit = min(limit, backing_limit);
		}
		put_ldev(device);
	}
	return limit;
}

struct drbd_request *find_oldest_request(struct drbd_resource *resource)
{
	/* Walk the transfer log,
	 * and find the oldest not yet completed request */
	struct drbd_request *r;
	list_for_each_entry(r, &resource->transfer_log, tl_requests) {
		if (atomic_read(&r->completion_ref))
			return r;
	}
	return NULL;
}

void request_timer_fn(unsigned long data)
{
	struct drbd_device *device = (struct drbd_device *) data;
	struct drbd_connection *connection;
	struct drbd_request *req; /* oldest request */
	unsigned long dt = 0, et = 0, nt; /* effective timeout = ko_count * timeout */
	bool restart_timer = false;
	unsigned long now = jiffies;

	rcu_read_lock();
	if (get_ldev(device)) { /* implicit state.disk >= D_INCONSISTENT */
		dt = rcu_dereference(device->ldev->disk_conf)->disk_timeout * HZ / 10;
		put_ldev(device);
	}
	rcu_read_unlock();

	spin_lock_irq(&device->resource->req_lock);
	req = find_oldest_request(device->resource);
	if (dt) {
		if (device->disk_state[NOW] > D_FAILED) {
			restart_timer = true;
			et = dt;
		}

		if (req && req->rq_state[0] & RQ_LOCAL_PENDING && req->device == device &&
		    time_after(now, req->start_time + dt) &&
		    !time_in_range(now, device->last_reattach_jif, device->last_reattach_jif + dt)) {
			drbd_warn(device, "Local backing device failed to meet the disk-timeout\n");
			__drbd_chk_io_error(device, DRBD_FORCE_DETACH);
		}
	}
	for_each_connection(connection, device->resource) {
		struct drbd_peer_device *peer_device;
		struct net_conf *nc;
		unsigned long ent = 0;
		int idx;

		rcu_read_lock();
		nc = rcu_dereference(connection->net_conf);
		if (nc && connection->cstate[NOW] == C_CONNECTED)
			ent = nc->timeout * HZ/10 * nc->ko_count;
		rcu_read_unlock();

		et = min_not_zero(et, ent);

		if (!ent)
			continue;

		restart_timer = true;
		peer_device = conn_peer_device(connection, device->vnr);
		idx = peer_device->bitmap_index;

		/* The request is considered timed out, if
		 * - we have some effective timeout from the configuration,
		 *   with above state restrictions applied,
		 * - the oldest request is waiting for a response from the network
		 *   resp. the local disk,
		 * - the oldest request is in fact older than the effective timeout,
		 * - the connection was established (resp. disk was attached)
		 *   for longer than the timeout already.
		 * Note that for 32bit jiffies and very stable connections/disks,
		 * we may have a wrap around, which is catched by
		 *   !time_in_range(now, last_..._jif, last_..._jif + timeout).
		 *
		 * Side effect: once per 32bit wrap-around interval, which means every
		 * ~198 days with 250 HZ, we have a window where the timeout would need
		 * to expire twice (worst case) to become effective. Good enough.
		 */

		if (req && req->rq_state[idx] & RQ_NET_PENDING &&
		    time_after(now, req->start_time + ent) &&
		    !time_in_range(now, connection->last_reconnect_jif, connection->last_reconnect_jif + ent)) {
			drbd_warn(device, "Remote failed to finish a request within ko-count * timeout\n");
			begin_state_change_locked(device->resource, CS_VERBOSE | CS_HARD);
			__change_cstate(connection, C_TIMEOUT);
			end_state_change_locked(device->resource);
		}
	}
	spin_unlock_irq(&device->resource->req_lock);

	if (restart_timer) {
		if (req)
			nt = (time_after(now, req->start_time + et) ? now : req->start_time) + et;
		else
			nt = now + et;
		mod_timer(&device->request_timer, nt);
	}
}
