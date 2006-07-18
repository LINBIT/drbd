/*
-*- linux-c -*-
   drbd_req.c
   Kernel module for 2.4.x/2.6.x Kernels

   This file is part of drbd by Philipp Reisner.

   Copyright (C) 1999-2006, Philipp Reisner <philipp.reisner@linbit.com>.
   Copyright (C) 2002-2006, Lars Ellenberg <lars.ellenberg@linbit.com>.
   Copyright (C) 2001-2006, LINBIT Information Technologies GmbH.

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
	if( !uptodate && mdev->bc->on_io_error == Detach) {
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

	drbd_req_free(req);

 out:
	if (test_bit(ISSUE_BARRIER,&mdev->flags)) {
		spin_lock_irqsave(&mdev->req_lock,flags);
		if(list_empty(&mdev->barrier_work.list)) {
			_drbd_queue_work(&mdev->data.work,&mdev->barrier_work);
		}
		spin_unlock_irqrestore(&mdev->req_lock,flags);
	}
}

static unsigned int ar_hash_fn(drbd_dev *mdev, sector_t sector)
{
	return (unsigned int)(sector) % APP_R_HSIZE;
}

int drbd_read_remote(drbd_dev *mdev, drbd_request_t *req)
{
	int rv;
	struct bio *bio = req->master_bio;

	req->w.cb = w_is_app_read;
	spin_lock(&mdev->pr_lock);
	INIT_HLIST_NODE(&req->colision);
	hlist_add_head( &req->colision, mdev->app_reads_hash +
			ar_hash_fn(mdev, drbd_req_get_sector(req) ));
	spin_unlock(&mdev->pr_lock);
	set_bit(UNPLUG_REMOTE,&mdev->flags);
	rv=drbd_send_drequest(mdev, DataRequest, bio->bi_sector, bio->bi_size,
			      (unsigned long)req);
	return rv;
}

int drbd_pr_verify(drbd_dev *mdev, drbd_request_t * req, sector_t sector)
{
	struct hlist_head *slot = mdev->app_reads_hash +
		ar_hash_fn(mdev, drbd_req_get_sector(req) );
	struct hlist_node *n;
	drbd_request_t * i;
	int rv=0;

	spin_lock(&mdev->pr_lock);

	hlist_for_each_entry(i, n, slot, colision) {
		if (i==req) {
			D_ASSERT(drbd_req_get_sector(i) == sector);
			rv=1;
			break;
		}
	}

	spin_unlock(&mdev->pr_lock);

	return rv;
}


/* we may do a local read if:
 * - we are consistent (of course),
 * - or we are generally inconsistent,
 *   BUT we are still/already IN SYNC for this area.
 *   since size may be bigger than BM_BLOCK_SIZE,
 *   we may need to check several bits.
 */
STATIC int drbd_may_do_local_read(drbd_dev *mdev, sector_t sector, int size)
{
	unsigned long sbnr,ebnr,bnr;
	sector_t esector, nr_sectors;

	if (mdev->state.disk == UpToDate) return 1;
	if (mdev->state.disk >= Outdated) return 0;
	if (mdev->state.disk <  Inconsistent) return 0;
	// state.disk == Inconsistent   We will have a look at the BitMap
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

static inline drbd_request_t* drbd_req_new(drbd_dev *mdev, struct bio *bio_src)
{
	struct bio *bio;
	drbd_request_t *req = mempool_alloc(drbd_request_mempool, GFP_NOIO);
	if (req) {
		SET_MAGIC(req);

		bio = bio_clone(bio_src, GFP_NOIO); /* XXX cannot fail?? */

		req->rq_status   = RQ_DRBD_NOTHING;
		req->mdev        = mdev;
		req->master_bio  = bio_src;
		req->private_bio = bio;

		bio->bi_private  = req;
		bio->bi_end_io   =
			bio_data_dir(bio) == WRITE
			? drbd_endio_write_pri
			: drbd_endio_read_pri;
		bio->bi_next    = 0;
	}
	return req;
}

STATIC int
drbd_make_request_common(drbd_dev *mdev, int rw, int size,
			 sector_t sector, struct bio *bio)
{
	drbd_request_t *req;
	int local, remote;

	/* allocate outside of all locks
	 */
	req = drbd_req_new(mdev,bio);
	if (!req) {
		/* only pass the error to the upper layers.
		 * if user cannot handle io errors, thats not our business.
		 */
		ERR("could not kmalloc() req\n");
		drbd_bio_IO_error(bio);
		return 0;
	}

	/* XXX req->w.cb = something; drbd_queue_work() ....
	 * Not yet.
	 */

	// down_read(mdev->device_lock);

	wait_event( mdev->cstate_wait,
		    (volatile int)((mdev->state.conn < WFBitMapS ||
				    mdev->state.conn > WFBitMapT) &&
				   !mdev->state.susp ) );

	local = inc_local(mdev);
	if (rw == READ || rw == READA) {
		if (local) {
			if (!drbd_may_do_local_read(mdev,sector,size)) {
				/* we could kick the syncer to
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

/* XXX SHARED DISK mode
 * think this over again for two primaries */

				local = 0;
				dec_local(mdev);
			}
		}
		remote = !local && mdev->state.pdsk >= UpToDate;//Consistent;
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
	if (rw == READA && mdev->state.disk >= Inconsistent && !local) {
		goto fail_and_free_req;
	}

	if (rw == WRITE && local)
		drbd_al_begin_io(mdev, sector);

	remote = remote && (mdev->state.pdsk == Inconsistent ||
			    mdev->state.pdsk == UpToDate);

	D_ASSERT( (rw != WRITE) || (remote == (mdev->state.conn >= Connected)) );

	if (!(local || remote)) {
		ERR("IO ERROR: neither local nor remote disk\n");
		goto fail_and_free_req;
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

	inc_ap_bio(mdev); // XXX maybe make this the first thing to do in drbd_make_request
	if (remote) {
		/* either WRITE and Connected,
		 * or READ, and no local disk,
		 * or READ, but not in sync.
		 */
		if (rw == WRITE) {

	/* About tl_add():
	1. This must be within the semaphor,
	   to ensure right order in tl_ data structure and to
	   ensure right order of packets on the write
	2. This must happen before sending, otherwise we might
	   get in the BlockAck packet before we have it on the
	   tl_ datastructure (=> We would want to remove it before it
	   is there!)
	3. Q: Why can we add it to tl_ even when drbd_send() might fail ?
	      There could be a tl_cancel() to remove it within the semaphore!
	   A: If drbd_send fails, we will lose the connection. Then
	      tl_cear() will simulate a RQ_DRBD_SEND and set it out of sync
	      for everything in the data structure.
	*/
			down(&mdev->data.mutex);
			if(test_and_clear_bit(ISSUE_BARRIER,&mdev->flags)) {
				struct drbd_barrier *b = tl_add_barrier(mdev);
				b->w.cb =  w_send_barrier;
				drbd_queue_work(mdev,&mdev->data.work, &b->w);
			}

			if (mdev->net_conf->two_primaries) {
				if(ee_have_write(mdev,req)) {
					WARN("Concurrent write! [DISCARD L] sec=%lu\n",
					     (unsigned long)sector);
					dec_local(mdev);
					dec_ap_pending(mdev);
					local=0;
					drbd_end_req(req, RQ_DRBD_DONE, 1, sector);
				}
			} else {
				tl_add(mdev,req);
			}
			req->w.cb =  w_send_dblock;
			drbd_queue_work(mdev,&mdev->data.work, &req->w);

			up(&mdev->data.mutex);
		} else {
			// this node is diskless ...
			inc_ap_pending(mdev);
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
		req->private_bio->bi_rw = rw;
		req->private_bio->bi_bdev = mdev->bc->backing_bdev;
		generic_make_request(req->private_bio);
	}

	// up_read(mdev->device_lock);
	return 0;

  fail_and_free_req:
	drbd_bio_IO_error(bio);
	drbd_req_free(req);
	return 0;
}

/* helper function for drbd_make_request
 * if we can determine just by the mdev (state) that this reques will fail,
 * return 1
 * otherwise return 0
 */
static int drbd_fail_request_early(drbd_dev* mdev, int is_write)
{
	if (unlikely(drbd_did_panic == DRBD_MAGIC))
		return 1;

	// Unconfigured
	if (mdev->state.conn == StandAlone &&
	    mdev->state.disk == Diskless)
		return 1;

	if (mdev->state.role != Primary &&
		( !disable_bd_claim || is_write) ) {
		if (DRBD_ratelimit(5*HZ,5)) {
			ERR("Process %s[%u] tried to %s; since we are not in Primary state, we cannot allow this\n",
			    current->comm, current->pid, is_write ? "WRITE" : "READ");
		}
		return 1;
	}

	/*
	 * Paranoia: we might have been primary, but sync target, or
	 * even diskless, then lost the connection.
	 * This should have been handled (panic? suspend?) somehwere
	 * else. But maybe it was not, so check again here.
	 * Caution: as long as we do not have a read/write lock on mdev,
	 * to serialize state changes, this is racy, since we may lose
	 * the connection *after* we test for the cstate.
	 */
	if ( mdev->state.disk <= Inconsistent &&
	     mdev->state.conn < Connected) {
		ERR("Sorry, I have no access to good data anymore.\n");
		/*
		 * FIXME suspend, loop waiting on cstate wait?
		 * panic?
		 */
		return 1;
	}


	return 0;
}

int drbd_make_request_26(request_queue_t *q, struct bio *bio)
{
	unsigned int s_enr,e_enr;
	struct Drbd_Conf* mdev = (drbd_dev*) q->queuedata;

/* FIXME
 * I think we need to grab some sort of reference count right here.
 * Would make it easier to serialize with size changes and other funny stuff.
 * Maybe move inc_ap_bio right here?
 */

	if (drbd_fail_request_early(mdev, bio_data_dir(bio) & WRITE)) {
		drbd_bio_IO_error(bio);
		return 0;
	}

	/*
	 * what we "blindly" assume:
	 */
	D_ASSERT(bio->bi_size > 0);
	D_ASSERT( (bio->bi_size & 0x1ff) == 0);
	D_ASSERT(bio->bi_size <= DRBD_MAX_SEGMENT_SIZE);
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

/* This is called by bio_add_page(). With this function we prevent
   that we get BIOs that span over multiple AL_EXTENTs.
 */
int drbd_merge_bvec(request_queue_t *q, struct bio *bio, struct bio_vec *bvec)
{
	unsigned int s = (unsigned int)bio->bi_sector << 9; // 32 bit...
	unsigned int t;

	if (bio->bi_size == 0) {
		s = max_t(unsigned int,
			  AL_EXTENT_SIZE - (s & (AL_EXTENT_SIZE-1)),
			  PAGE_SIZE);
		// As long as the BIO is emtpy we allow at least one page.
	} else {
		t = s & ~(AL_EXTENT_SIZE-1);
		s = (s + bio->bi_size);

		if( ( s & ~(AL_EXTENT_SIZE-1) ) != t ) {
			s = 0;
			// This BIO already spans over an AL_EXTENTs boundary.
		} else {
			s = AL_EXTENT_SIZE - ( s & (AL_EXTENT_SIZE-1) );
			// Bytes to the next AL_EXTENT boundary.
		}
	}

	return s;
}
