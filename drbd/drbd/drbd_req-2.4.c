/*
-*- linux-c -*-
   drbd.c
   Kernel module for 2.4.x Kernels

   This file is part of drbd by Philipp Reisner.

   Copyright (C) 1999-2003, Philipp Reisner <philipp.reisner@gmx.at>.
	main author.

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

#ifdef HAVE_AUTOCONF
#include <linux/autoconf.h>
#endif
#ifdef CONFIG_MODVERSIONS
#include <linux/modversions.h>
#endif

#include <linux/slab.h>
#include "drbd.h"
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

	PARANOIA_BUG_ON(!IS_VALID_MDEV(mdev));
	PARANOIA_BUG_ON(drbd_req_get_sector(req) != rsector);
	spin_lock_irqsave(&mdev->req_lock,flags);

	if(req->rq_status & nextstate) {
		ERR("request state error(%d)\n", req->rq_status);
	}

	req->rq_status |= nextstate;
	req->rq_status &= er_flags | ~0x0001;
	if( (req->rq_status & RQ_DRBD_DONE) == RQ_DRBD_DONE ) goto end_it;

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
		}
	}

	if(mdev->conf.wire_protocol==DRBD_PROT_C && mdev->cstate > Connected) {
		drbd_set_in_sync(mdev,rsector,drbd_req_get_size(req));
	}

	/// TODO look at mdev->on_io_error
	/// in the Detach case do not report it to the application.
	drbd_bio_endio(req->master_bio,(req->rq_status & 0x0001));


	INVALIDATE_MAGIC(req);
	mempool_free(req,drbd_request_mempool);

	if (test_bit(ISSUE_BARRIER,&mdev->flags))
		wake_asender(mdev);
}

int drbd_read_remote(drbd_dev *mdev, drbd_request_t *req)
{
	int rv;
	drbd_bio_t *bio = req->master_bio;

	spin_lock(&mdev->pr_lock);
	list_add(&req->w.list,&mdev->new_app_reads);
	spin_unlock(&mdev->pr_lock);
	inc_ap_pending(mdev);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
	rv=drbd_send_drequest(mdev, DataRequest, bio->b_rsector, bio->b_size,
			      (unsigned long)req);
#else
	rv=drbd_send_drequest(mdev, DataRequest, bio->bi_sector, bio->bi_size,
			      (unsigned long)req);
#endif
	return rv;
}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0)
int drbd_merge_bvec_fn(request_queue_t *q, struct bio *bio, struct bio_vec *bv)
{
	drbd_dev * const mdev = q->queuedata;
	sector_t sector = bio->bi_sector;
	int lo_max = PAGE_SIZE, max = PAGE_SIZE;
	const unsigned long chunk_sectors = AL_EXTENT_SIZE >> 9;

	D_ASSERT(bio->bi_size == 0);

	if (mdev->backing_bdev) {
		request_queue_t * const b = mdev->backing_bdev->bd_disk->queue;
		if (b->merge_bvec_fn)
			lo_max = b->merge_bvec_fn(b,bio,bv);
	}
	max = (chunk_sectors - (sector & (chunk_sectors - 1))) << 9;
	max = min(lo_max,max);
	// if (max < 0) max = 0; /* bio_add cannot handle a negative return */
	return min((int)PAGE_SIZE,max);
}
#endif

STATIC int
drbd_make_request_common(drbd_dev *mdev, int rw, int size,
			 sector_t sector, drbd_bio_t *bio)
{
	drbd_request_t *req;
	int local, remote;
	int target_area_out_of_sync = FALSE; // only relevant for reads

	/* allocate outside of all locks
	 */
	req = mempool_alloc(drbd_request_mempool, GFP_DRBD);
	if (!req) {
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

	local = inc_local(mdev);
	// FIXME special case handling of READA ??
	if (rw == READ || rw == READA) {
		if (local) {
			target_area_out_of_sync =
				(mdev->cstate == SyncTarget) &&
				bm_get_bit(mdev->mbds_id,sector,size);
			if (target_area_out_of_sync) {
				/* whe could kick the syncer to
				 * sync this extent asap, wait for
				 * it, then continue locally.
				 * Or just issue the request remotely.
				 */
				local = 0;
				dec_local(mdev);
			}
		}
		remote = !local;
	} else {
		remote = 1;
	}
	remote = remote && (mdev->cstate >= Connected)
			&& !test_bit(PARTNER_DISKLESS,&mdev->flags);

	if (!(local || remote)) {
		ERR("IO ERROR: neither local nor remote disk\n");
		// PANIC ??
		drbd_bio_IO_error(bio);
		return 0;
	}

	/* THINK
	 * maybe we need to
	 *   if (rw == WRITE) drbd_al_begin_io(mdev, sector);
	 * right here already?
	 */

	/* do this first, so I do not need to call drbd_end_req,
	 * but can set the rq_status directly.
	 */
	if (!local)
		req->rq_status |= RQ_DRBD_LOCAL;
	if (!remote)
		req->rq_status |= RQ_DRBD_SENT;

	if (remote) {
		/* either WRITE and Connected,
		 * or READ, and no local disk,
		 * or READ, but not in sync.
		 */
		drbd_plug_device(mdev);
		if (rw == WRITE) {
			/* Syncronization with the syncer is done
			 * via drbd_[rs|al]_[begin|end]_io()
			 */
			if(mdev->conf.wire_protocol != DRBD_PROT_A) {
				inc_ap_pending(mdev);
			}
			/* THINK drbd_send_dblock has a return value,
			 * but we ignore it here. Is it actually void,
			 * because error handling takes place elsewhere?
			 */
			drbd_send_dblock(mdev,req);
		} else if (target_area_out_of_sync) {
			drbd_read_remote(mdev,req);
		} else {
			// this node is diskless ...
			drbd_read_remote(mdev,req);
		}
	}

	if (local) {
		if (rw == WRITE) {
			drbd_al_begin_io(mdev, sector);
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
		drbd_generic_make_request(rw,&req->private_bio);
	}

	// up_read(mdev->device_lock);
	return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
int drbd_make_request_24(request_queue_t *q, int rw, struct buffer_head *bh)
{
	struct Drbd_Conf* mdev = drbd_conf + MINOR(bh->b_rdev);
	if (MINOR(bh->b_rdev) >= minor_count || mdev->cstate < StandAlone) {
		buffer_IO_error(bh);
		return 0;
	}

	return drbd_make_request_common(mdev,rw,bh->b_size,bh->b_rsector,bh);
}
#else
int drbd_make_request_26(request_queue_t *q, struct bio *bio)
{
	struct Drbd_Conf* mdev = (drbd_dev*) q->queuedata;
	if (mdev->cstate < StandAlone) {
		drbd_bio_IO_error(bio);
		return 0;
	}
	return drbd_make_request_common(mdev,bio_rw(bio),bio->bi_size,bio->bi_sector,bio);
}
#endif
