/*
   drbd_req.h
   Kernel module for 2.6.x Kernels

   This file is part of DRBD

   Copyright (C) 2006, Lars Ellenberg <lars.ellenberg@linbit.com>.
   Copyright (C) 2006, LINBIT Information Technologies GmbH.

   DRBD is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   DRBD is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with drbd; see the file COPYING.  If not, write to
   the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef _DRBD_REQ_H
#define _DRBD_REQ_H

#include <linux/config.h>
#include <linux/module.h>

#include <linux/slab.h>
#include <linux/drbd.h>
#include "drbd_int.h"

/* The request callbacks will be called in irq context by the IDE drivers,
   and in Softirqs/Tasklets/BH context by the SCSI drivers,
   and by the receiver and worker in kernel-thread context.
   Try to get the locking right :) */

/*
 * Objects of type drbd_request_t do only exist on a Primary node, and are
 * associated with IO requests originating from the block layer above us.
 *
 * There are quite a few things that may happen to a drbd request
 * during its lifetime.
 *
 *  It will be created.
 *  It will be marked with the intention to be
 *    submitted to local disk and/or
 *    send via the network.
 *
 *  It has to be placed on the transfer log and other housekeeping lists,
 *  In case we have a network connection.
 *    FIXME I believe that for consistency we should place even READ requests
 *    on these lists, so we can moan when we detect that the other node is
 *    writing to an area that we currently read from (when this happens, our
 *    users are broken).
 *
 *  It may be identified as a concurrent (write) request
 *    and be handled accordingly.
 *
 *  It may me handed over to the local disk subsystem.
 *  It may be completed by the local disk subsystem,
 *    either sucessfully or with io-error.
 *  In case it is a READ request, and it failed locally,
 *    it may be retried remotely.
 *
 *  It may be queued for sending.
 *  It may be handed over to the network stack,
 *    which may fail.
 *  It may be acknowledged by the "peer" according to the wire_protocol in use.
 *    this may be a negative ack.
 *  It may receive a faked ack when the network connection is lost and the
 *  transfer log is cleaned up.
 *  Sending may be canceled due to network connection loss.
 *  When it finally has outlived its time,
 *    corresponding dirty bits in the resync-bitmap may be cleared or set,
 *    it will be destroyed,
 *    and completion will be signalled to the originator,
 *      with or without "success".
 *
 * See also documentation/drbd-request-state-overview.dot
 *  (dot -Tps2 documentation/drbd-request-state-overview.dot | display -)
 */

typedef enum {
	created,
	to_be_send,
	to_be_submitted,

	suspend_because_of_conflict,
	conflicting_req_done,
	conflicting_ee_done,

	/* XXX yes, now I am inconsistent...
	 * these two are not "events" but "actions"
	 * oh, well... */
	queue_for_net_write,
	queue_for_net_read,

	send_canceled,
	send_failed,
	handed_over_to_network,
	connection_lost_while_pending,
	recv_acked_by_peer,
	write_acked_by_peer,
	neg_acked,
	barrier_acked, /* in protocol A and B */
	data_received, /* (remote read) */

	read_completed_with_error,
	write_completed_with_error,
	completed_ok,
} drbd_req_event_t;

/* encoding of request states for now.  we don't actually need that many bits.
 * we don't need to do atomic bit operations either, since most of the time we
 * need to look at the connection state and/or manipulate some lists at the
 * same time, so we should hold the request lock anyways.
 */
enum drbd_req_state_bits {
	/* 210
	 * 000: no local possible
	 * 001: to be submitted
	 *    UNUSED, we could map: 011: submitted, completion still pending
	 * 110: completed ok
	 * 010: completed with error
	 */
	__RQ_LOCAL_PENDING,
	__RQ_LOCAL_COMPLETED,
	__RQ_LOCAL_OK,

	/* 76543
	 * 00000: no network possible
	 * 00001: to be send
	 * 00011: to be send, on worker queue
	 * 00101: sent, expecting recv_ack (B) or write_ack (C)
	 * 11101: sent,
	 *        recv_ack (B) or implicit "ack" (A),
	 *        still waiting for the barrier ack.
	 *        master_bio may already be completed and invalidated.
	 * 11100: write_acked (C),
	 *        data_received (for remote read, any protocol)
	 *        or finally the barrier ack has arrived (B,A)...
	 *        request can be freed
	 * 01100: neg-acked (write, protocol C)
	 *        or neg-d-acked (read, any protocol)
	 *        or killed from the transfer log
	 *        during cleanup after connection loss
	 *        request can be freed
	 * 01000: canceled or send failed...
	 *        request can be freed
	 */

	/* if "SENT" is not set, yet, this can still fail or be canceled.
	 * if "SENT" is set already, we still wait for an Ack packet.
	 * when cleared, the master_bio may be completed.
	 * in (B,A) the request object may still linger on the transaction log
	 * until the corresponding barrier ack comes in */
	__RQ_NET_PENDING,

	/* If it is QUEUED, and it is a WRITE, it is also registered in the
	 * transfer log. Currently we need this flag to avoid conflicts between
	 * worker canceling the request and tl_clear_barrier killing it from
	 * transfer log.  We should restructure the code so this conflict does
	 * no longer occur. */
	__RQ_NET_QUEUED,

	/* well, actually only "handed over to the network stack" */
	__RQ_NET_SENT,

     	/* when set, the request may be freed.
	 * in (C) this happens when WriteAck is received,
	 * in (B,A) when the corresponding BarrierAck is received */
	__RQ_NET_DONE,

	/* whether or not we know (C) or pretend (B,A) that the write
	 * was successfully written on the peer.
	 */
	__RQ_NET_OK,
};

#define RQ_LOCAL_PENDING   (1UL << __RQ_LOCAL_PENDING)
#define RQ_LOCAL_COMPLETED (1UL << __RQ_LOCAL_COMPLETED)
#define RQ_LOCAL_OK        (1UL << __RQ_LOCAL_OK)

#define RQ_LOCAL_MASK      ((RQ_LOCAL_OK << 1)-1) /* 0x07 */

#define RQ_NET_PENDING     (1UL << __RQ_NET_PENDING)
#define RQ_NET_QUEUED      (1UL << __RQ_NET_QUEUED)
#define RQ_NET_SENT        (1UL << __RQ_NET_SENT)
#define RQ_NET_DONE        (1UL << __RQ_NET_DONE)
#define RQ_NET_OK          (1UL << __RQ_NET_OK)

#define RQ_NET_MASK        (((RQ_NET_OK << 1)-1) & ~RQ_LOCAL_MASK) /* 0xf8 */

/* epoch entries */
static struct hlist_head* ee_hash_slot(drbd_dev *mdev, sector_t sector)
{
	BUG_ON(mdev->ee_hash_s == 0);
	return mdev->ee_hash + ((unsigned int)(sector>>HT_SHIFT) % mdev->ee_hash_s);
}

/* transfer log (drbd_request objects) */
static struct hlist_head* tl_hash_slot(drbd_dev *mdev, sector_t sector)
{
	BUG_ON(mdev->tl_hash_s == 0);
	return mdev->tl_hash +
		((unsigned int)(sector>>HT_SHIFT) % mdev->tl_hash_s);
}

/* when we receive the answer for a read request,
 * verify that we actually know about it */
static inline drbd_request_t* _ack_id_to_req(drbd_dev *mdev,u64 id, sector_t sector)
{
	struct hlist_head *slot = tl_hash_slot(mdev,sector);
	struct hlist_node *n;
	drbd_request_t * req;

	hlist_for_each_entry(req, n, slot, colision) {
		if ((unsigned long)req == (unsigned long)id) {
			if (req->sector != sector) {
				ERR("_ack_id_to_req: found req %p but it has "
				    "wrong sector (%llx versus %llx)\n", req,
				    (unsigned long long)req->sector,
				    (unsigned long long)sector);
				break;
			}
			return req;
		}
	}
	ERR("_ack_id_to_req: failed to find req %p, sector %llx in list\n", 
		(void*)(unsigned long)id, (unsigned long long)sector);
	return NULL;
}

/* application reads (drbd_request objects) */
static struct hlist_head* ar_hash_slot(drbd_dev *mdev, sector_t sector)
{
	return mdev->app_reads_hash
		+ ((unsigned int)(sector) % APP_R_HSIZE);
}

/* when we receive the answer for a read request,
 * verify that we actually know about it */
static inline drbd_request_t* _ar_id_to_req(drbd_dev *mdev,u64 id, sector_t sector)
{
	struct hlist_head *slot = ar_hash_slot(mdev,sector);
	struct hlist_node *n;
	drbd_request_t * req;

	hlist_for_each_entry(req, n, slot, colision) {
		if ((unsigned long)req == (unsigned long)id) {
			D_ASSERT(req->sector == sector);
			return req;
		}
	}
	return NULL;
}

static inline drbd_request_t* drbd_req_new(drbd_dev *mdev, struct bio *bio_src)
{
	struct bio *bio;
	drbd_request_t *req = mempool_alloc(drbd_request_mempool, GFP_NOIO);
	if (likely(req)) {
		bio = bio_clone(bio_src, GFP_NOIO); /* XXX cannot fail?? */

		req->rq_state    = 0;
		req->mdev        = mdev;
		req->master_bio  = bio_src;
		req->private_bio = bio;
		req->epoch       = 0;
		req->sector      = bio->bi_sector;
		req->size        = bio->bi_size;
		INIT_HLIST_NODE(&req->colision);

		bio->bi_private  = req;
		bio->bi_end_io   = drbd_endio_pri;
		bio->bi_next    = 0;
	}
	return req;
}

static inline void drbd_req_free(drbd_request_t *req)
{
	mempool_free(req,drbd_request_mempool);
}

static inline int overlaps(sector_t s1, int l1, sector_t s2, int l2)
{
	return !( ( s1 + (l1>>9) <= s2 ) || ( s1 >= s2 + (l2>>9) ) );
}

static inline void _req_may_be_done(drbd_request_t *req)
{
	const unsigned long s = req->rq_state;
	drbd_dev *mdev = req->mdev;
	int rw;

	MUST_HOLD(&mdev->req_lock)

	if (s & RQ_NET_PENDING) return;
	if (s & RQ_LOCAL_PENDING) return;

	if (req->master_bio) {
		/* this is data_received (remote read)
		 * or protocol C WriteAck
		 * or protocol B RecvAck
		 * or protocol A "handed_over_to_network" (SendAck)
		 * or canceled or failed,
		 * or killed from the transfer log due to connection loss.
		 */

		/*
		 * figure out whether to report success or failure.
		 *
		 * report success when at least one of the oprations suceeded.
		 * or, to put the other way,
		 * only report failure, when both operations failed.
		 *
		 * what to do about the failures is handled elsewhere.
		 * what we need to do here is just: complete the master_bio.
		 */
		int ok = (s & RQ_LOCAL_OK) || (s & RQ_NET_OK);
		rw = bio_data_dir(req->master_bio); 
		if (rw == WRITE) {
			drbd_request_t *i;
			struct Tl_epoch_entry *e;
			struct hlist_node *n;
			struct hlist_head *slot;

			/* before we can signal completion to the upper layers,
			 * we may need to close the current epoch */
			if (req->epoch == mdev->newest_barrier->br_number)
				set_bit(ISSUE_BARRIER,&mdev->flags);

			/* and maybe "wake" those conflicting requests that
			 * wait for this request to finish.
			 * we just have to walk starting from req->next,
			 * see _req_add_hash_check_colision(); */
#define OVERLAPS overlaps(req->sector, req->size, i->sector, i->size)
			n = req->colision.next;
			/* hlist_del ... done below */
			hlist_for_each_entry_from(i, n, colision) {
				if (OVERLAPS)
					drbd_queue_work(&mdev->data.work,&i->w);
			}

			/* and maybe "wake" those conflicting epoch entries
			 * that wait for this request to finish */
			/* FIXME looks alot like we could consolidate some code
			 * and maybe even hash tables? */
#undef OVERLAPS
#define OVERLAPS overlaps(req->sector, req->size, e->sector, e->size)
			slot = ee_hash_slot(mdev,req->sector);
			hlist_for_each_entry(e, n, slot, colision) {
				if (OVERLAPS)
					drbd_queue_work(&mdev->data.work,&e->w);
			}
#undef OVERLAPS
		}
		/* else: READ, READA: nothing more to do */

		/* remove the request from the conflict detection
		 * respective block_id verification hash */
		hlist_del(&req->colision);

		/* FIXME not yet implemented...
		 * in case we got "suspended" (on_disconnect: freeze io)
		 * we may not yet complete the request...
		 * though, this is probably best handled elsewhere by not
		 * walking the transfer log until "unfreeze", so we won't end
		 * up here anyways during the freeze ...
		 * then again, if it is a READ, it is not in the TL at all.
		 * is it still leagal to complete a READ during freeze? */
		bio_endio(req->master_bio, req->master_bio->bi_size, ok ? 0 : -EIO);
		req->master_bio = NULL;
	} else {
		/* only WRITE requests can end up here without a master_bio */
		rw = WRITE;
	}

	if ((s == RQ_NET_MASK) == 0 || (s & RQ_NET_DONE)) {
		/* this is disconnected (local only) operation,
		 * or protocol C WriteAck,
		 * or protocol A or B BarrierAck,
		 * or killed from the transfer log due to connection loss. */

		/* if it was a write, we may have to set the corresponding
		 * bit(s) out-of-sync first. If it had a local part, we need to
		 * release the reference to the activity log. */
		if (rw == WRITE) {
			/* remove it from the transfer log */
			list_del(&req->tl_requests);
			/* Set out-of-sync unless both OK flags are set 
			 * (local only or remote failed).
			 * Other places where we set out-of-sync:
			 * READ with local io-error */
			if (!(s & RQ_NET_OK) || !(s & RQ_LOCAL_OK))
				drbd_set_out_of_sync(mdev,req->sector,req->size);
			if (s & RQ_LOCAL_MASK) {
				drbd_al_complete_io(mdev, req->sector);
			}
		}

		/* if it was an io error, we want to notify our
		 * peer about that, and see if we need to
		 * detach the disk and stuff.
		 * to avoid allocating some special work
		 * struct, reuse the request. */
		if (rw == WRITE &&
		    (( s & RQ_LOCAL_MASK) && !(s & RQ_LOCAL_OK))) {
			if (!(req->w.list.next == LIST_POISON1 ||
			      list_empty(&req->w.list))) {
				/* DEBUG ASSERT only; if this triggers, we
				 * probably corrupt the worker list here */
				DUMPP(req->w.list.next);
				DUMPP(req->w.list.prev);
			}
			req->w.cb = w_io_error;
			drbd_queue_work(&mdev->data.work, &req->w);
			/* drbd_req_free() is done in w_io_error */
		} else {
			drbd_req_free(req);
		}
	}
	/* else: network part and not DONE yet. that is
	 * protocol A or B, barrier ack still pending... */
}

/*
 * checks whether there was an overlapping request already registered.
 * if so, add the request to the colision hash
 *        _after_ the (first) overlapping request,
 * 	  and return 1
 * if no overlap was found, add this request to the front of the chain,
 *        and return 0
 *
 * corresponding hlist_del is in _req_may_be_done()
 *
 * NOTE:
 * paranoia: assume something above us is broken, and issues different write
 * requests for the same block simultaneously...
 *
 * To ensure these won't be reordered differently on both nodes, resulting in
 * diverging data sets, we discard the later one(s). Not that this is supposed
 * to happen, but this is the rationale why we also have to check for
 * conflicting requests with local origin, and why we have to do so regardless
 * of whether we allowed multiple primaries.
 *
 * BTW, in case we only have one primary, the ee_hash is empty anyways, and the
 * second hlist_for_each_entry becomes a noop. This is even simpler than to
 * grab a reference on the net_conf, and check for the two_primaries flag...
 */
static int _req_add_hash_check_colision(drbd_request_t *req)
{
	drbd_dev *mdev = req->mdev;
	const sector_t sector = req->sector;
	const int size = req->size;
	drbd_request_t *i;
	struct Tl_epoch_entry *e;
	struct hlist_node *n;
	struct hlist_head *slot;

	MUST_HOLD(&mdev->req_lock);
	D_ASSERT(hlist_unhashed(&req->colision));
#define OVERLAPS overlaps(i->sector, i->size, sector, size)
	slot = tl_hash_slot(mdev,sector);
	hlist_for_each_entry(i, n, slot, colision) {
		if (OVERLAPS) {
			ALERT("%s[%u] Concurrent local write detected!"
			      "	[DISCARD L] new: %llu +%d; pending: %llu +%d\n",
			      current->comm, current->pid,
			      (unsigned long long)sector, size,
			      (unsigned long long)i->sector, i->size);
			hlist_add_after(n,&req->colision);
			return 1;
		}
	}
	/* no overlapping request with local origin found,
	 * register in front */
	hlist_add_head(&req->colision,slot);

	/* now, check for overlapping requests with remote origin */
#undef OVERLAPS
#define OVERLAPS overlaps(e->sector, e->size, sector, size)
	slot = ee_hash_slot(mdev,sector);
	hlist_for_each_entry(e, n, slot, colision) {
		if (OVERLAPS) {
			ALERT("%s[%u] Concurrent remote write detected!"
			      "	[DISCARD L] new: %llu +%d; pending: %llu +%d\n",
			      current->comm, current->pid,
			      (unsigned long long)sector, size,
			      e->sector, e->size);
			return 1;
		}
	}
#undef OVERLAPS

	/* this is like it should be, and what we expected.
	 * out users do behave after all... */
	return 0;
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
 * Though I think it is likely that we break this again into many
 * static inline void _req_mod_ ## what (req) ...
 */
static inline void _req_mod(drbd_request_t *req, drbd_req_event_t what)
{
	drbd_dev *mdev = req->mdev;
	MUST_HOLD(&mdev->req_lock);

	switch(what) {
	default:
		ERR("LOGIC BUG in %s:%u\n", __FILE__ , __LINE__ );
		return;

	/* does not happen...
	 * initialization done in drbd_req_new
	case created:
		break;
		*/

	case to_be_send: /* via network */
		/* reached via drbd_make_request_common
		 * and from FIXME w_read_retry_remote */
		D_ASSERT(!(req->rq_state & RQ_NET_MASK));
		req->rq_state |= RQ_NET_PENDING;
		inc_ap_pending(mdev);
		break;

	case to_be_submitted: /* locally */
		/* reached via drbd_make_request_common */
		D_ASSERT(!(req->rq_state & RQ_LOCAL_MASK));
		req->rq_state |= RQ_LOCAL_PENDING;
		break;

#if 0
		/* done inline below */
	case suspend_because_of_conflict:
		/* assert something? */
		/* reached via drbd_make_request_common */
		/* update state flag? why? which one? */
		req->w.cb = w_req_cancel_conflict;
		/* no queue here, see below! */
		break;
#endif

	/* FIXME these *_completed_* are basically the same.
	 * can probably be merged with some if (what == xy) */

	case completed_ok:
		if (bio_data_dir(req->private_bio) == WRITE)
			mdev->writ_cnt += req->size>>9;
		else
			mdev->read_cnt += req->size>>9;

		bio_put(req->private_bio);
		req->private_bio = NULL;
		dec_local(mdev);

		req->rq_state |= (RQ_LOCAL_COMPLETED|RQ_LOCAL_OK);
		req->rq_state &= ~RQ_LOCAL_PENDING;

		_req_may_be_done(req);
		break;

	case write_completed_with_error:
		req->rq_state |= RQ_LOCAL_COMPLETED;
		req->rq_state &= ~RQ_LOCAL_PENDING;

		bio_put(req->private_bio);
		req->private_bio = NULL;
		dec_local(mdev);
		ALERT("Local WRITE failed sec=%llu size=%u\n",
					req->sector, req->size);
		/* and now: check how to handle local io error.
		 * FIXME see comment below in read_completed_with_error */
		__drbd_chk_io_error(mdev);
		_req_may_be_done(req);
		break;

	case read_completed_with_error:
		drbd_set_out_of_sync(mdev,req->sector,req->size);
		req->rq_state |= RQ_LOCAL_COMPLETED;
		req->rq_state &= ~RQ_LOCAL_PENDING;

		bio_put(req->private_bio);
		req->private_bio = NULL;
		dec_local(mdev);
		if (bio_rw(req->master_bio) == READA)
			/* it is legal to fail READA */
			break;
		/* else */
		ALERT("Local READ failed sec=%llu size=%u\n",
					req->sector, req->size);
		/* _req_mod(req,to_be_send); oops, recursion in static inline */
		D_ASSERT(!(req->rq_state & RQ_NET_MASK));
		req->rq_state |= RQ_NET_PENDING;
		inc_ap_pending(mdev);

		/* and now: check how to handle local io error.
		 *
		 * FIXME we should not handle WRITE and READ io errors
		 * the same. When we retry the READ, and then write
		 * the answer, that might suceed because modern drives
		 * would relocate the sectors. We'd need to keep our
		 * private bio then, and round the offset and size so
		 * we get back enough data to be able to clear the bits again.
		 */
		__drbd_chk_io_error(mdev);
		/* fall through: _req_mod(req,queue_for_net_read); */

	case queue_for_net_read:
		/* READ or READA, and
		 * no local disk,
		 * or target area marked as invalid,
		 * or just got an io-error. */
		/* from drbd_make_request_common
		 * or from bio_endio during read io-error recovery */

		/* so we can verify the handle in the answer packet
		 * corresponding hlist_del is in _req_may_be_done() */
		hlist_add_head(&req->colision, ar_hash_slot(mdev,req->sector));

		set_bit(UNPLUG_REMOTE,&mdev->flags); /* why? */

		D_ASSERT(req->rq_state & RQ_NET_PENDING);
		req->rq_state |= RQ_NET_QUEUED;
		req->w.cb = (req->rq_state & RQ_LOCAL_MASK)
			? w_read_retry_remote
			: w_send_read_req;
		drbd_queue_work(&mdev->data.work, &req->w);
		break;

	case queue_for_net_write:
		/* assert something? */
		/* from drbd_make_request_common only */

		/* NOTE
		 * In case the req ended up on the transfer log before being
		 * queued on the worker, it could lead to this request being
		 * missed during cleanup after connection loss.
		 * So we have to do both operations here,
		 * within the same lock that protects the transfer log.
		 */

		/* register this request on the colison detection hash
		 * tables. if we have a conflict, just leave here.
		 * the request will be "queued" for faked "completion"
		 * once the conflicting request is done.
		 */
		if (_req_add_hash_check_colision(req)) {
			/* this is a conflicting request.
			 * even though it may have been only _partially_
			 * overlapping with one of the currently pending requests,
			 * without even submitting or sending it,
			 * we will pretend that it was successfully served
			 * once the pending conflicting request is done.
			 */
			/* _req_mod(req, suspend_because_of_conflict); */
			/* this callback is just for ASSERT purposes */
			req->w.cb = w_req_cancel_conflict;

			/* we don't add this to any epoch (barrier) object.
			 * assign the "invalid" barrier_number 0.
			 * it should be 0 anyways, still,
			 * but being explicit won't harm. */
			req->epoch = 0;

			/*
			 * EARLY break here!
			 */
			break;
		}

		/* _req_add_to_epoch(req); this has to be after the
		 * _maybe_start_new_epoch(req); which happened in
		 * drbd_make_request_common, because we now may set the bit
		 * again ourselves to close the current epoch.
		 *
		 * Add req to the (now) current epoch (barrier). */

		/* see drbd_make_request_common just after it grabs the req_lock */
		D_ASSERT(test_bit(ISSUE_BARRIER, &mdev->flags) == 0);

		req->epoch = mdev->newest_barrier->br_number;
		list_add(&req->tl_requests,&mdev->newest_barrier->requests);

		/* mark the current epoch as closed,
		 * in case it outgrew the limit */
		if( ++mdev->newest_barrier->n_req >= mdev->net_conf->max_epoch_size )
			set_bit(ISSUE_BARRIER,&mdev->flags);

		D_ASSERT(req->rq_state & RQ_NET_PENDING);
		req->rq_state |= RQ_NET_QUEUED;
		req->w.cb =  w_send_dblock;
		drbd_queue_work(&mdev->data.work, &req->w);
		break;

	case conflicting_req_done:
	case conflicting_ee_done:
		/* reached via bio_endio of the
		 * conflicting request or epoch entry.
		 * we now just "fake" completion of this request.
		 * THINK: I'm going to _FAIL_ this request.
		 */
		D_ASSERT(req->w.cb == w_req_cancel_conflict);
		D_ASSERT(req->epoch == 0);
		{
			const unsigned long s = req->rq_state;
			if (s & RQ_LOCAL_MASK) {
				D_ASSERT(s & RQ_LOCAL_PENDING);
				bio_put(req->private_bio);
				req->private_bio = NULL;
				dec_local(mdev);
			}
			D_ASSERT((s & RQ_NET_MASK) == RQ_NET_PENDING);
			dec_ap_pending(mdev);
		}
		/* no _OK ... this is going to be an io-error */
		req->rq_state = RQ_LOCAL_COMPLETED|RQ_NET_DONE;
		_req_may_be_done(req);
		break;

	/* FIXME
	 * to implement freeze-io,
	 * we may not finish the request just yet.
	 */
	case send_canceled:
		/* for the request, this is the same thing */
	case send_failed:
		D_ASSERT(req->rq_state & RQ_NET_PENDING);
		dec_ap_pending(mdev);
		req->rq_state &= ~(RQ_NET_PENDING|RQ_NET_QUEUED|RQ_NET_OK);
		req->rq_state |= RQ_NET_DONE;
		_req_may_be_done(req);
		break;

	case handed_over_to_network:
		/* assert something? */
		if ( bio_data_dir(req->master_bio) == WRITE &&
		     mdev->net_conf->wire_protocol == DRBD_PROT_A ) {
			/* this is what is dangerous about protocol A:
			 * pretend it was sucessfully written on the peer.
			 * FIXME in case we get a local io-error in
			 * protocol != C, we might want to defer comletion
			 * until we get the barrier ack, and send a NegAck
			 * in case the other node had an io-error, too...
			 * That way we would at least not report "success"
			 * if it was not written at all. */
			if (req->rq_state & RQ_NET_PENDING) {
				dec_ap_pending(mdev);
				req->rq_state &= ~RQ_NET_PENDING;
				req->rq_state |= RQ_NET_OK;
			} /* else: neg-ack was faster... */
			/* it is still not yet RQ_NET_DONE until the
			 * corresponding epoch barrier got acked as well,
			 * so we know what to dirty on connection loss */
		}
		req->rq_state &= ~RQ_NET_QUEUED;
		req->rq_state |= RQ_NET_SENT;
		/* because _drbd_send_zc_bio could sleep, and may want to
		 * dereference the bio even after the "write_acked_by_peer" and
		 * "completed_ok" events came in, once we return from
		 * _drbd_send_zc_bio (drbd_send_dblock), we have to check
		 * whether it is done already, and end it.  */
		_req_may_be_done(req);
		break;

	case connection_lost_while_pending:
		/* transfer log cleanup after connection loss */
		/* assert something? */
		if (req->rq_state & RQ_NET_PENDING) dec_ap_pending(mdev);
		req->rq_state &= ~(RQ_NET_OK|RQ_NET_PENDING);
		req->rq_state |= RQ_NET_DONE;
		/* if it is still queued, we may not complete it here.
		 * it will be canceled soon.
		 * FIXME we should change the code so this can not happen. */
		if (!(req->rq_state & RQ_NET_QUEUED)) 
			_req_may_be_done(req);
		break;

	case write_acked_by_peer:
		/* assert something? */
		/* protocol C; successfully written on peer */
		req->rq_state |= RQ_NET_DONE;
		/* rest is the same as for: */
	case recv_acked_by_peer:
		/* protocol B; pretends to be sucessfully written on peer.
		 * see also notes above in handed_over_to_network about
		 * protocol != C */
		req->rq_state |= RQ_NET_OK;
		D_ASSERT(req->rq_state & RQ_NET_PENDING);
		dec_ap_pending(mdev);
		req->rq_state &= ~RQ_NET_PENDING;
		if (req->rq_state & RQ_NET_SENT)
			_req_may_be_done(req);
		/* else: done by handed_over_to_network */
		break;

	case neg_acked:
		/* assert something? */
		if (req->rq_state & RQ_NET_PENDING) dec_ap_pending(mdev);
		req->rq_state &= ~(RQ_NET_OK|RQ_NET_PENDING);
		/* FIXME THINK! is it DONE now, or is it not? */
		req->rq_state |= RQ_NET_DONE;
		if (req->rq_state & RQ_NET_SENT)
			_req_may_be_done(req);
		/* else: done by handed_over_to_network */
		break;

	case barrier_acked:
		/* can even happen for protocol C,
		 * when local io is stil pending.
		 * in which case it does nothing. */
		D_ASSERT(req->rq_state & RQ_NET_SENT);
		req->rq_state |= RQ_NET_DONE;
		_req_may_be_done(req);
		break;

	case data_received:
		D_ASSERT(req->rq_state & RQ_NET_PENDING);
		dec_ap_pending(mdev);
		req->rq_state &= ~RQ_NET_PENDING;
		req->rq_state |= (RQ_NET_OK|RQ_NET_DONE);
		/* can it happen that we receive the DataReply
		 * before the send DataRequest function returns? */
		if (req->rq_state & RQ_NET_SENT)
			_req_may_be_done(req);
		/* else: done by handed_over_to_network */
		break;
	};
}

/* If you need it irqsave, do it your self! */
static inline void req_mod(drbd_request_t *req, drbd_req_event_t what)
{
	spin_lock_irq(&req->mdev->req_lock);
	_req_mod(req,what);
	spin_unlock_irq(&req->mdev->req_lock);
}
#endif
