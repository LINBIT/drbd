/*
-*- linux-c -*-
   drbd_req.c
   Kernel module for 2.4.x/2.6.x Kernels

   This file is part of drbd by Philipp Reisner.

   Copyright (C) 1999-2004, Philipp Reisner <philipp.reisner@linbit.com>.
	main author.

   Copyright (C) 2002-2004, Lars Ellenberg <l.g.e@web.de>.
	main contributor.

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

#include <linux/config.h>
#include <linux/module.h>

#include <linux/slab.h>
#include <linux/drbd.h>
#include "drbd_int.h"

void drbd_end_req(drbd_request_t *req, int nextstate, int er_flags,
		  sector_t rsector)
{
	/* This callback will be called in irq context by the IDE drivers,
	   and in Softirqs/Tasklets/BH context by the SCSI drivers.
	   This function is called by the receiver in kernel-thread context.
	   Try to get the locking right :) */

	struct Drbd_Conf* mdev = drbd_req_get_mdev(req);
	unsigned long flags=0;
	int uptodate;

	PARANOIA_BUG_ON(!IS_VALID_MDEV(mdev));
	PARANOIA_BUG_ON(drbd_req_get_sector(req) != rsector);
	spin_lock_irqsave(&mdev->req_lock,flags);

	if(req->rq_status & nextstate) {
		ERR("request state error(%d)\n", req->rq_status);
	}

	req->rq_status |= nextstate;
	req->rq_status &= er_flags | ~0x0001;
	if( (req->rq_status & RQ_DRBD_DONE) == RQ_DRBD_DONE ) {
		goto end_it;
	}

	spin_unlock_irqrestore(&mdev->req_lock,flags);

	return;

/* We only report uptodate == TRUE if both operations (WRITE && SEND)
   reported uptodate == TRUE
 */

	end_it:
	spin_unlock_irqrestore(&mdev->req_lock,flags);

	if( req->rq_status & RQ_DRBD_IN_TL ) {
		if( ! ( er_flags & ERF_NOTLD ) ) {
			/*If this call is from tl_clear() we may not call 
			  tl_dependene, otherwhise we have a homegrown 
			  spinlock deadlock.   */
			if(tl_dependence(mdev,req))
				set_bit(ISSUE_BARRIER,&mdev->flags);
		} else {
			list_del(&req->w.list); // we have the tl_lock...
			hlist_del(&req->colision);
		}
	}

	uptodate = req->rq_status & 0x0001;
	if( !uptodate && mdev->on_io_error == Detach) {
		drbd_set_out_of_sync(mdev,rsector, drbd_req_get_size(req));
		// It should also be as out of sync on
		// the other side!  See w_io_error()

		drbd_bio_endio(req->master_bio,1);
		dec_ap_bio(mdev);
		// The assumption is that we wrote it on the peer.

// FIXME proto A and diskless :)

		req->w.cb = w_io_error;
		drbd_queue_work(mdev,&mdev->data.work,&req->w);

		goto out;

	}

	drbd_bio_endio(req->master_bio,uptodate);
	dec_ap_bio(mdev);

	INVALIDATE_MAGIC(req);
	mempool_free(req,drbd_request_mempool);

 out:
	if (test_bit(ISSUE_BARRIER,&mdev->flags)) {
		spin_lock_irqsave(&mdev->req_lock,flags);
		if(list_empty(&mdev->barrier_work.list)) {
			_drbd_queue_work(&mdev->data.work,&mdev->barrier_work);
		}
		spin_unlock_irqrestore(&mdev->req_lock,flags);
	}
}

int drbd_read_remote(drbd_dev *mdev, drbd_request_t *req)
{
	int rv;
	struct bio *bio = req->master_bio;

	req->w.cb = w_is_app_read;
	spin_lock(&mdev->pr_lock);
	list_add(&req->w.list,&mdev->app_reads);
	spin_unlock(&mdev->pr_lock);
	set_bit(UNPLUG_REMOTE,&mdev->flags);
	rv=drbd_send_drequest(mdev, DataRequest, bio->bi_sector, bio->bi_size,
			      (unsigned long)req);
	return rv;
}


/* we may do a local read if:
 * - we are consistent (of course),
 * - or we are generally inconsistent,
 *   BUT we are still/already IN SYNC for this area.
 *   since size may be up to PAGE_SIZE, but BM_BLOCK_SIZE may be smaller
 *   than PAGE_SIZE, we may need to check several bits.
 */
STATIC int drbd_may_do_local_read(drbd_dev *mdev, sector_t sector, int size)
{
	unsigned long sbnr,ebnr,bnr;
	sector_t esector, nr_sectors;

	if (mdev->state.s.disk == UpToDate) return 1;

	nr_sectors = drbd_get_capacity(mdev->this_bdev);
	esector = sector + (size>>9) -1;

	D_ASSERT(sector  < nr_sectors);
	D_ASSERT(esector < nr_sectors);

	sbnr = BM_SECT_TO_BIT(sector);
	ebnr = BM_SECT_TO_BIT(esector);

	for (bnr = sbnr; bnr <= ebnr; bnr++) {
		if (drbd_bm_test_bit(mdev,bnr)) return 0;
	}
	return 1;
}

STATIC int
drbd_make_request_common(drbd_dev *mdev, int rw, int size,
			 sector_t sector, struct bio *bio)
{
	drbd_request_t *req;
	int local, remote;
	int target_area_out_of_sync = FALSE; // only relevant for reads

	if (unlikely(drbd_did_panic == DRBD_MAGIC)) {
		drbd_bio_IO_error(bio);
		return 0;
	}

	/* FIXME
	 * not always true, e.g. someone trying to mount on Secondary
	 * maybe error out immediately here?
	 */
	D_ASSERT(mdev->state.s.role == Primary);

	/*
	 * Paranoia: we might have been primary, but sync target, or
	 * even diskless, then lost the connection.
	 * This should have been handled (panic? suspend?) somehwere
	 * else. But maybe it was not, so check again here.
	 * Caution: as long as we do not have a read/write lock on mdev,
	 * to serialize state changes, this is racy, since we may lose
	 * the connection *after* we test for the cstate.
	 */
	if ( mdev->state.s.disk <= Inconsistent && 
	     mdev->state.s.conn < Connected) {
		ERR("Sorry, I have no access to good data anymore.\n");
/*
  FIXME suspend, loop waiting on cstate wait? panic?
*/
		drbd_bio_IO_error(bio);
		return 0;
	}

	/* allocate outside of all locks
	 */
	req = mempool_alloc(drbd_request_mempool, GFP_DRBD);
	if (!req) {
		/* only pass the error to the upper layers.
		 * if user cannot handle io errors, thats not our business.
		 */
		ERR("could not kmalloc() req\n");
		drbd_bio_IO_error(bio);
		return 0;
	}
	SET_MAGIC(req);
	req->master_bio = bio;

	// XXX maybe merge both variants into one
	if (rw == WRITE) drbd_req_prepare_write(mdev,req);
	else             drbd_req_prepare_read(mdev,req);

	/* XXX req->w.cb = something; drbd_queue_work() ....
	 * Not yet.
	 */

	// down_read(mdev->device_lock);

	wait_event( mdev->cstate_wait,
		    (volatile int)(mdev->state.s.conn < WFBitMapS || 
				   mdev->state.s.conn > WFBitMapT) );

	local = inc_local(mdev);
	if (rw == READ || rw == READA) {
		if (local) {
			if (!drbd_may_do_local_read(mdev,sector,size)) {
				/* whe could kick the syncer to
				 * sync this extent asap, wait for
				 * it, then continue locally.
				 * Or just issue the request remotely.
				 */
				/* FIXME
				 * I think we have a RACE here. We request
				 * something from the peer, then later some
				 * write starts ...  and finished *before*
				 * the answer to the read comes in, because
				 * the ACK for the WRITE goes over
				 * meta-socket ...
				 * Maybe we need to properly lock reads
				 * against the syncer, too. But if we have
				 * some user issuing writes on an area that
				 * he has pending reads on, _he_ is really
				 * broke anyways, and would get "undefined
				 * results" on _any_ io stack, even just the
				 * local io stack.
				 */
				local = 0;
				dec_local(mdev);
			}
		}
		remote = !local && mdev->state.s.pdsk >= UpToDate;//Consistent;
	} else {
		remote = 1;
	}

	/* If we have a disk, but a READA request is mapped to remote,
	 * we are Primary, Inconsistent, SyncTarget.
	 * Just fail that READA request right here.
	 *
	 * THINK: maybe fail all READA when not local?
	 *        or make this configurable...
	 *        if network is slow, READA won't do any good.
	 */
	if (rw == READA && mdev->state.s.disk >= Inconsistent && !local) {
		drbd_bio_IO_error(bio);
		return 0;
	}

	if (rw == WRITE && local)
		drbd_al_begin_io(mdev, sector);

	remote = remote && (mdev->state.s.pdsk >= Inconsistent);

	if (!(local || remote)) {
		ERR("IO ERROR: neither local nor remote disk\n");
		// FIXME PANIC ??
		drbd_bio_IO_error(bio);
		return 0;
	}

	/* do this first, so I do not need to call drbd_end_req,
	 * but can set the rq_status directly.
	 */
	if (!local)
		req->rq_status |= RQ_DRBD_LOCAL;
	if (!remote)
		req->rq_status |= RQ_DRBD_SENT;

	/* we need to plug ALWAYS since we possibly need to kick lo_dev */
	drbd_plug_device(mdev);

	inc_ap_bio(mdev);
	if (remote) {
		/* either WRITE and Connected,
		 * or READ, and no local disk,
		 * or READ, but not in sync.
		 */
		inc_ap_pending(mdev);
		if (rw == WRITE) {
			switch(drbd_send_dblock(mdev,req)) {
			case 0: /* sending failed */
				if (mdev->state.s.conn >= Connected)
					drbd_force_state(mdev,NS(conn,NetworkFailure));
				dec_ap_pending(mdev);
				drbd_thread_restart_nowait(&mdev->receiver);
				break;
			case -1: /* concurrent write */
				WARN("Concurrent write! [DISCARD L] sec=%lu\n",
				     (unsigned long)sector);
				dec_local(mdev);
				dec_ap_pending(mdev);
				local=0;
				drbd_end_req(req, RQ_DRBD_DONE, 1, sector);
				break;
			default: /* block was sent */
				if(mdev->conf.wire_protocol == DRBD_PROT_A) {
					dec_ap_pending(mdev);
					drbd_end_req(req, RQ_DRBD_SENT, 1, sector);
				}
			}
		} else if (target_area_out_of_sync) {
			drbd_read_remote(mdev,req);
		} else {
			// this node is diskless ...
			drbd_read_remote(mdev,req);
		}
	}

	/* NOTE: drbd_send_dlobck() must happen before start of local IO,
	         to get he concurrent write detection right. */

	if (local) {
		if (rw == WRITE) {
			if (!remote) drbd_set_out_of_sync(mdev,sector,size);
		} else {
			D_ASSERT(!remote);
		}
		/* FIXME
		 * Should we add even local reads to some list, so
		 * they can be grabbed and freed somewhen?
		 *
		 * They already have a reference count (sort of...)
		 * on mdev via inc_local()
		 */
		if(rw == WRITE) mdev->writ_cnt += size>>9;
		else            mdev->read_cnt += size>>9;

		// in 2.4.X, READA are submitted as READ.
		drbd_generic_make_request(rw,drbd_req_private_bio(req));
	}

	// up_read(mdev->device_lock);
	return 0;
}

int drbd_make_request_26(request_queue_t *q, struct bio *bio)
{
	unsigned int s_enr,e_enr;
	struct Drbd_Conf* mdev = (drbd_dev*) q->queuedata;
	if (mdev->state.s.disk < Inconsistent) {
		drbd_bio_IO_error(bio);
		return 0;
	}

	/*
	 * what we "blindly" assume:
	 */
	D_ASSERT(bio->bi_size > 0);
	D_ASSERT( (bio->bi_size & 0x1ff) == 0);
	D_ASSERT(bio->bi_size <= PAGE_SIZE);
	D_ASSERT(bio->bi_vcnt == 1);
	D_ASSERT(bio->bi_idx == 0);

	s_enr = bio->bi_sector >> (AL_EXTENT_SIZE_B-9);
	e_enr = (bio->bi_sector+(bio->bi_size>>9)-1) >> (AL_EXTENT_SIZE_B-9);
	D_ASSERT(e_enr >= s_enr);

	if(unlikely(s_enr != e_enr)) {
		/* This bio crosses an AL_EXTENT boundary, so we have to
		 * split it. [So far, only XFS is known to do this...]
		 */
		struct bio_pair *bp;
		bp = bio_split(bio, bio_split_pool, 
			       (e_enr<<(AL_EXTENT_SIZE_B-9)) - bio->bi_sector);
		drbd_make_request_26(q,&bp->bio1);
		drbd_make_request_26(q,&bp->bio2);
		bio_pair_release(bp);
		return 0;
	}

	return drbd_make_request_common(mdev,bio_rw(bio),bio->bi_size,
					bio->bi_sector,bio);
}
