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

	if( ! ( er_flags & ERF_NOTLD ) ) {
		/*If this call is from tl_clear() we may not call tl_dependene,
		  otherwhise we have a homegrown spinlock deadlock.   */
		if(tl_dependence(mdev,req))
			set_bit(ISSUE_BARRIER,&mdev->flags);
	} else {
		list_del(&req->w.list); // we have the tl_lock...
	}

	if(mdev->conf.wire_protocol==DRBD_PROT_C && mdev->cstate > Connected) {
		drbd_set_in_sync(mdev,rsector,drbd_req_get_size(req));
	}

	drbd_bio_endio(req->master_bio,(req->rq_status & 0x0001));

	if( mdev->do_panic && !(req->rq_status & 0x0001) ) {
		drbd_panic(DEVICE_NAME": The lower-level device had an error.\n");
	}

	INVALIDATE_MAGIC(req);
	mempool_free(req,drbd_request_mempool);

	if (test_bit(ISSUE_BARRIER,&mdev->flags))
		wake_asender(mdev);
}

STATIC struct Pending_read*
drbd_find_read(sector_t sector, struct list_head *in)
{
	struct list_head *le;
	struct Pending_read *pr;

	list_for_each(le,in) {
		pr = list_entry(le, struct Pending_read, w.list);
		if(pr->d.sector == sector) return pr;
	}

	return NULL;
}

STATIC void drbd_issue_drequest(struct Drbd_Conf* mdev,drbd_bio_t *bio)
{
	struct Pending_read *pr;
	pr = mempool_alloc(drbd_pr_mempool, GFP_DRBD);

	if (!pr) {
		ERR("could not kmalloc() pr\n");
		drbd_bio_IO_error(bio);
		return;
	}
	SET_MAGIC(pr);

	pr->d.master_bio = bio;
	pr->cause = Application;
	spin_lock(&mdev->pr_lock);
	list_add(&pr->w.list,&mdev->app_reads);
	spin_unlock(&mdev->pr_lock);
	inc_ap_pending(mdev);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
	drbd_send_drequest(mdev, DataRequest, bio->b_rsector, bio->b_size,
			   (unsigned long)pr);
#else
	//WORK_HERE
#warning "FIXME make 2.6.x clean"
#endif
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
	return min(PAGE_SIZE,max);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
int drbd_make_request(request_queue_t *q, int rw, struct buffer_head *bio)
#else
int drbd_make_request(request_queue_t *q, struct bio *bio)
#endif
{
	struct Drbd_Conf* mdev =
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
		drbd_conf + MINOR(bio->b_rdev);
#else
		(drbd_dev*) q->queuedata;
#endif
	drbd_request_t *req;
	int send_ok;
	int sector, size;
	ONLY_IN_26(int rw = bio_rw(bio);)

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
	if (MINOR(bio->b_rdev) >= minor_count || mdev->cstate < StandAlone) {
		buffer_IO_error(bio);
		return 0;
	}

#else
#warning "FIXME"
#endif

	/* what do we know?
	 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
	sector = bio->b_rsector;
	size   = bio->b_size;
#else
	//      rw = bio->bi_rw & RW_MASK;
	//      ra = bio->bi_rw & RWA_MASK;
	      size = bio->bi_size;
	    sector = bio->bi_sector;
	/* barrier = bio_barrier(bio);
	nr_sectors = bio_sectors(bio); */
#endif

	if( mdev->lo_file == 0 ) {
		if( mdev->cstate < Connected ) {
			drbd_bio_IO_error(bio);
			return 0;
		}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
		if(!test_and_set_bit(WRITE_HINT_QUEUED,&mdev->flags)) {
			queue_task(&mdev->write_hint_tq, &tq_disk); // IO HINT
		}
#else
		spin_lock_irq(q->queue_lock);
		if(!blk_queue_plugged(q)) {
			blk_plug_device(q);
			del_timer(&q->unplug_timer);
			// unplugging should not happen automatically...
		}
		spin_unlock_irq(q->queue_lock);
#endif


		// Fail READA ??
		if( rw == WRITE ) {
			req = mempool_alloc(drbd_request_mempool, GFP_DRBD);

			if (!req) {
				ERR("could not kmalloc() req\n");
				drbd_bio_IO_error(bio);
				return 0;
			}
			SET_MAGIC(req);

			//WORK_HERE
			/* FIXME the drbd_make_request function will be
			 * restructured soon.
			 * until that is the case,
			 * at least put the mdev and sector number into the
			 * private bh!
			 */
			req->master_bio = bio;
			drbd_req_prepare_write(mdev,req);
			req->rq_status  = RQ_DRBD_WRITTEN | 1;

			if(mdev->conf.wire_protocol != DRBD_PROT_A) {
				inc_ap_pending(mdev);
			}
			drbd_send_dblock(mdev,req); // FIXME error check?
		} else { // rw == READ || rw == READA
			drbd_issue_drequest(mdev,bio);
		}
		return 0; // Ok everything arranged
	}

	if ( mdev->cstate == SyncTarget &&
	     bm_get_bit(mdev->mbds_id,sector,size) ) {
		struct Pending_read *pr;
		if( rw == WRITE ) {
			// Actually nothing special to do.
			// Just do a mirrored write.
			// Syncronization with the syncer is done
			// via drbd_[rs|al]_[begin|end]_io()
		} else { // rw == READ || rw == READA
			spin_lock(&mdev->pr_lock);
			pr=drbd_find_read(sector,&mdev->resync_reads);
			if(pr) {
				INFO("Upgraded a resync read\n");

				pr->cause |= Application;
				inc_ap_pending(mdev);
				pr->d.master_bio=bio;
				list_del(&pr->w.list);
				list_add(&pr->w.list,&mdev->app_reads);
				spin_unlock(&mdev->pr_lock);
				return 0; // Ok everything arranged
			}

			spin_unlock(&mdev->pr_lock);
			drbd_issue_drequest(mdev,bio);
			return 0;
		}
	}

	if( rw == READ || rw == READA ) {
		mdev->read_cnt += size >> 9;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
		bio->b_rdev = mdev->lo_device;
#else
#warning "FIXME"
			//WORK_HERE
		/* I want to change it anyways so we never remap ... */
#endif
		return 1; // Not arranged for transfer ( but remapped :)
	}

	mdev->writ_cnt += size >> 9;

	if(mdev->cstate<Connected || test_bit(PARTNER_DISKLESS,&mdev->flags)) {
		drbd_set_out_of_sync(mdev,sector,size);

		drbd_al_begin_io(mdev, sector);
		drbd_al_complete_io(mdev, sector); // FIXME TODO
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
		bio->b_rdev = mdev->lo_device;
#else
#warning "FIXME"
			//WORK_HERE
		/* I want to change it anyways so we never remap ... */
#endif
		return 1; // Not arranged for transfer ( but remapped :)
	}

	// Now its clear that we have to do a mirrored write:

	req = mempool_alloc(drbd_request_mempool, GFP_DRBD);

	if (!req) {
		ERR("could not kmalloc() req\n");
		drbd_bio_IO_error(bio);
		return 0;
	}
	SET_MAGIC(req);

	req->master_bio = bio;
	drbd_req_prepare_write(mdev,req);

	send_ok=drbd_send_dblock(mdev,req);

	// FIXME we could remove the send_ok cases, the are redundant to tl_clear()
	if(send_ok && mdev->conf.wire_protocol!=DRBD_PROT_A) inc_ap_pending(mdev);
	if(mdev->conf.wire_protocol==DRBD_PROT_A || (!send_ok) ) {
				/* If sending failed, we can not expect
				   an ack packet. */
		drbd_end_req(req, RQ_DRBD_SENT, 1, drbd_req_get_sector(req));
	}
	if(!send_ok) drbd_set_out_of_sync(mdev,sector,size);

NOT_IN_26(
	if(!test_and_set_bit(WRITE_HINT_QUEUED,&mdev->flags)) {
		queue_task(&mdev->write_hint_tq, &tq_disk);
	}
)

	drbd_al_begin_io(mdev, drbd_req_get_sector(req));

	drbd_generic_make_request(rw,&req->private_bio);

	return 0; /* Ok, bh arranged for transfer */

}

