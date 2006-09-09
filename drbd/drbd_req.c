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
#include "drbd_req.h"

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

/*
 * general note:
 * looking at the state (conn, disk, susp, pdsk) outside of the spinlock that
 * protects the state changes is inherently racy.
 *
 * FIXME verify this rationale why we may do so anyways:
 *
 * I think it "should" be like this:
 * as soon as we have a "ap_bio_cnt" reference we may test for "bad" states,
 * because the transition from "bad" to "good" states may only happen while no
 * application request is on the fly, so once we are positive about a "bad"
 * state, we know it won't get better during the lifetime of this request.
 *
 * In case we think we are ok, but "asynchronously" some interrupt or other thread
 * marks some operation as impossible, we are still ok, since we would just try
 * anyways, and then see that it does not work there and then.
 */

STATIC int
drbd_make_request_common(drbd_dev *mdev, int rw, int size,
			 sector_t sector, struct bio *bio)
{
	struct drbd_barrier *b = NULL;
	drbd_request_t *req;
	int local, remote;

	/* allocate outside of all locks; get a "reference count" (ap_bio_cnt)
	 * to avoid races with the disconnect/reconnect code.  */
	inc_ap_bio(mdev);
	req = drbd_req_new(mdev,bio);
	if (!req) {
		dec_ap_bio(mdev);
		/* only pass the error to the upper layers.
		 * if user cannot handle io errors, thats not our business. */
		ERR("could not kmalloc() req\n");
		bio_endio(bio, bio->bi_size, -ENOMEM);
		return 0;
	}

	/* we wait here
	 *    as long as the device is suspended
	 *    until the bitmap is no longer on the fly during connection handshake
	 */
	wait_event( mdev->cstate_wait,
		    (volatile int)((mdev->state.conn < WFBitMapS ||
				    mdev->state.conn > WFBitMapT) &&
				   !mdev->state.susp ) );

	local = inc_local(mdev);
	if (!local) {
		bio_put(req->private_bio); /* or we get a bio leak */
		req->private_bio = NULL;
	}
	if (rw == WRITE) {
		remote = 1;
	} else {
		/* READ || READA */
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
				bio_put(req->private_bio);
				req->private_bio = NULL;
				dec_local(mdev);
			}
		}
		remote = !local && mdev->state.pdsk >= UpToDate;//Consistent;
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

	/* For WRITES going to the local disk, grab a reference on the target extent.
	 * This waits for any resync activity in the corresponding resync
	 * extent to finish, and, if necessary, pulls in the target extent into
	 * the activity log, which involves further disk io because of transactional
	 * on-disk meta data updates. */
	if (rw == WRITE && local)
		drbd_al_begin_io(mdev, sector);

	remote = remote && (mdev->state.pdsk == UpToDate ||
			    ( mdev->state.pdsk == Inconsistent &&
			      mdev->state.conn >= Connected ) );

	D_ASSERT( (rw != WRITE) || (remote == (mdev->state.conn >= Connected)) );

	if (!(local || remote)) {
		ERR("IO ERROR: neither local nor remote disk\n");
		goto fail_and_free_req;
	}

	/* we need to plug ALWAYS since we possibly need to kick lo_dev
	 * FIXME I'd like to put this within the req_lock, too... */
	drbd_plug_device(mdev);

	/* For WRITE request, we have to make sure that we have an
	 * unused_spare_barrier, in case we need to start a new epoch.
	 * I try to be smart and avoid to pre-allocate always "just in case",
	 * but there is a race between testing the bit and pointer outside the
	 * spinlock, and grabbing the spinlock.
	 * if we lost that race, we retry.  */
	if (rw == WRITE && remote &&
	    mdev->unused_spare_barrier == NULL &&
	    test_bit(ISSUE_BARRIER,&mdev->flags))
	{
  allocate_barrier:
		b = kmalloc(sizeof(struct drbd_barrier),GFP_NOIO);
		if(!b) {
			ERR("Failed to alloc barrier.");
			goto fail_and_free_req;
		}
	}

	/* GOOD, everything prepared, grab the spin_lock */
	spin_lock_irq(&mdev->req_lock);

	if (b && mdev->unused_spare_barrier == NULL) {
		mdev->unused_spare_barrier = b;
		b = NULL;
	}
	if (rw == WRITE && remote &&
	    mdev->unused_spare_barrier == NULL &&
	    test_bit(ISSUE_BARRIER,&mdev->flags)) {
		/* someone closed the current epoch
		 * while we were grabbing the spinlock */
		spin_unlock_irq(&mdev->req_lock);
		goto allocate_barrier;
	}

	/* _maybe_start_new_epoch(mdev);
	 * If we need to generate a write barrier packet, we have to add the
	 * new epoch (barrier) object, and queue the barrier packet for sending,
	 * and queue the req's data after it _within the same lock_, otherwise
	 * we have race conditions were the reorder domains could be mixed up.
	 *
	 * Even read requests may start a new epoch and queue the corresponding
	 * barrier packet.  To get the write ordering right, we only have to
	 * make sure that, if this is a write request and it triggered a
	 * barrier packet, this request is queued within the same spinlock. */
	if (mdev->unused_spare_barrier &&
            test_and_clear_bit(ISSUE_BARRIER,&mdev->flags)) {
		struct drbd_barrier *b = mdev->unused_spare_barrier;
		b = _tl_add_barrier(mdev,b);
		b->w.cb =  w_send_barrier;
		drbd_queue_work(&mdev->data.work, &b->w);
	} else {
		D_ASSERT(!(remote && rw == WRITE &&
			   test_bit(ISSUE_BARRIER,&mdev->flags)));
	}

	/* NOTE
	 * Actually, 'local' may be wrong here already, since we may have failed
	 * to write to the meta data, and may become wrong anytime because of
	 * local io-error for some other request, which would lead to us
	 * "detaching" the local disk.
	 *
	 * 'remote' may become wrong any time because the network could fail.
	 *
	 * This is a harmless race condition, though, since it is handled
	 * correctly at the appropriate places; so it just deferres the failure
	 * of the respective operation.
	 */

	/* mark them early for readability.
	 * this just sets some state flags. */
	if (remote) _req_mod(req, to_be_send);
	if (local)  _req_mod(req, to_be_submitted);

	/* NOTE remote first: to get he concurrent write detection right, we
	 * must register the request before start of local IO.  */
	if (remote) {
		/* either WRITE and Connected,
		 * or READ, and no local disk,
		 * or READ, but not in sync.
		 */
		_req_mod(req, rw == WRITE
				? queue_for_net_write
				: queue_for_net_read);
	}

	/* still holding the req_lock.
	 * not strictly neccessary, but for the statistic counters... */

#if 0
	if (local) {
		/* FIXME I think this branch can go completely.  */
		if (rw == WRITE) {
			/* we defer the drbd_set_out_of_sync to the bio_endio
			 * function. we only need to make sure the bit is set
			 * before we do drbd_al_complete_io. */
			 if (!remote) drbd_set_out_of_sync(mdev,sector,size);
		} else {
			D_ASSERT(!remote); /* we should not read from both */
		}
		/* FIXME
		 * Should we add even local reads to some list, so
		 * they can be grabbed and freed somewhen?
		 *
		 * They already have a reference count (sort of...)
		 * on mdev via inc_local()
		 */

		/* XXX we probably should not update these here but in bio_endio.
		 * especially the read_cnt could go wrong for all the READA
		 * that may just be failed because of "overload"... */
		if(rw == WRITE) mdev->writ_cnt += size>>9;
		else            mdev->read_cnt += size>>9;

		/* FIXME what ref count do we have to ensure the backing_bdev
		 * was not detached below us? */
		req->private_bio->bi_rw = rw; /* redundant */
		req->private_bio->bi_bdev = mdev->bc->backing_bdev;
	}
#endif

	req->private_bio->bi_bdev = mdev->bc->backing_bdev;
	spin_unlock_irq(&mdev->req_lock);
	if (b) kfree(b); /* if someone else has beaten us to it... */

	/* extra if branch so I don't need to write spin_unlock_irq twice */

	if (local) {
		BUG_ON(req->private_bio->bi_bdev == NULL);
		generic_make_request(req->private_bio);
	}
	return 0;

  fail_and_free_req:
	bio_endio(bio, bio->bi_size, -EIO);
	drbd_req_free(req);
	return 0;
}

/* helper function for drbd_make_request
 * if we can determine just by the mdev (state) that this request will fail,
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

	if (drbd_fail_request_early(mdev, bio_data_dir(bio) & WRITE)) {
		bio_endio(bio, bio->bi_size, -EPERM);
		return 0;
	}

	/*
	 * what we "blindly" assume:
	 */
	D_ASSERT(bio->bi_size > 0);
	D_ASSERT( (bio->bi_size & 0x1ff) == 0);
	D_ASSERT(bio->bi_size <= q->max_segment_size);
	D_ASSERT(bio->bi_idx == 0);

#if 1
	/* to make some things easier, force allignment of requests within the
	 * granularity of our hash tables */
	s_enr = bio->bi_sector >> HT_SHIFT;
	e_enr = (bio->bi_sector+(bio->bi_size>>9)-1) >> HT_SHIFT;
#else
	/* when not using two primaries (and not being as paranoid as lge),
	 * actually there is no need to be as strict.
	 * only force allignment within AL_EXTENT boundaries */
	s_enr = bio->bi_sector >> (AL_EXTENT_SIZE_B-9);
	e_enr = (bio->bi_sector+(bio->bi_size>>9)-1) >> (AL_EXTENT_SIZE_B-9);
#endif
	D_ASSERT(e_enr >= s_enr);

	if(unlikely(s_enr != e_enr)) {
		/* This bio crosses some boundary, so we have to split it.
		 * [So far, only XFS is known to do this...] */
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

/* This is called by bio_add_page().  With this function we reduce
 * the number of BIOs that span over multiple AL_EXTENTs.
 *
 * we do the calculation within the lower 32bit of the byte offsets,
 * since we don't care for actual offset, but only check whether it
 * would cross "activity log extent" boundaries.
 *
 * As long as the BIO is emtpy we have to allow at least one bvec,
 * regardless of size and offset.  so the resulting bio may still
 * cross extent boundaries.  those are dealt with (bio_split) in
 * drbd_make_request_26.
 */
/* FIXME for two_primaries,
 * we should use DRBD_MAX_SEGMENT_SIZE instead of AL_EXTENT_SIZE */
int drbd_merge_bvec(request_queue_t *q, struct bio *bio, struct bio_vec *bvec)
{
	unsigned int bio_offset = (unsigned int)bio->bi_sector << 9; // 32 bit...
	unsigned int bio_size = bio->bi_size;
	int max;

	max = AL_EXTENT_SIZE - ((bio_offset & (AL_EXTENT_SIZE-1)) + bio_size);
	if (max < 0) max = 0;
	if (max <= bvec->bv_len && bio_size == 0)
		return bvec->bv_len;
	else
		return max;
}
