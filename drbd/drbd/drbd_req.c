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

void drbd_end_req(drbd_request_t *req, int nextstate, int er_flags)
{
	/* This callback will be called in irq context by the IDE drivers,
	   and in Softirqs/Tasklets/BH context by the SCSI drivers.
	   This function is called by the receiver in kernel-thread context.
	   Try to get the locking right :) */

	struct Drbd_Conf* mdev = drbd_conf + MINOR(req->bh->b_rdev);
	unsigned long flags=0;

	spin_lock_irqsave(&mdev->req_lock,flags);

	if(req->rq_status & nextstate) {
		ERR("request state error(%d)\n", req->rq_status);
	}

	req->rq_status = req->rq_status | nextstate | (er_flags & 0x0001);
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
		list_del(&req->list); // we have the tl_lock...
	}

	spin_lock_irqsave(&mdev->bb_lock,flags);
	bb_done(mdev,APP_BH_SECTOR(req->bh));
	spin_unlock_irqrestore(&mdev->bb_lock,flags);

	req->bh->b_end_io(req->bh,(0x0001 & er_flags & req->rq_status));

	if( mdev->do_panic && !(0x0001 & er_flags & req->rq_status) ) {
		panic(DEVICE_NAME": The lower-level device had an error.\n");
	}

	mempool_free(req,drbd_request_mempool);
	SET_MAGIC(req);

	if (test_bit(ISSUE_BARRIER,&mdev->flags))
		wake_asender(mdev);
}

void drbd_dio_end(struct buffer_head *bh, int uptodate)
{
	struct Drbd_Conf* mdev;
	drbd_request_t *req;

	req = bh->b_private;
	mdev = drbd_conf+MINOR(req->bh->b_rdev);

	drbd_end_req(req, RQ_DRBD_WRITTEN, uptodate);
	// BIG TODO: Only set it, iff it is the case!
	drbd_set_in_sync(mdev, APP_BH_SECTOR(req->bh), req->bh->b_size);
	drbd_al_complete_io(mdev,bh->b_rsector);
	kmem_cache_free(bh_cachep, bh);
}

STATIC struct Pending_read*
drbd_find_read(sector_t sector, struct list_head *in)
{
	struct list_head *le;
	struct Pending_read *pr;

	list_for_each(le,in) {
		pr = list_entry(le, struct Pending_read, list);
		if(pr->d.sector == sector) return pr;
	}

	return NULL;
}

STATIC void drbd_issue_drequest(struct Drbd_Conf* mdev,struct buffer_head *bh)
{
	struct Pending_read *pr;
	pr = mempool_alloc(drbd_pr_mempool, GFP_DRBD);

	if (!pr) {
		ERR("could not kmalloc() pr\n");
		bh->b_end_io(bh,0);
		return;
	}
	SET_MAGIC(pr);

	pr->d.bh = bh;
	pr->cause = mdev->cstate == SyncTarget ? AppAndResync : Application;
	spin_lock(&mdev->pr_lock);
	list_add(&pr->list,&mdev->app_reads);
	spin_unlock(&mdev->pr_lock);
	inc_pending(mdev);
	drbd_send_drequest(mdev, mdev->cstate == SyncTarget ? RSDataRequest : DataRequest,
			   bh->b_rsector, bh->b_size,
			   (unsigned long)pr);
}


int drbd_make_request(request_queue_t *q, int rw, struct buffer_head *bh)
{
	struct Drbd_Conf* mdev = drbd_conf + MINOR(bh->b_rdev);
	struct buffer_head *nbh;
	drbd_request_t *req;
	int send_ok;

#if 0
	{
		static const char *strs[3] =
		{
			[READ]="READ",
			[READA]="READA",
			[WRITE]="WRITE",
		};

		/* I don't understand it yet, but
		 * drbdadm primary drbd0 ; drbdadm invalidate drbd0 ;
		 * dd if=/dev/zero of=/dev/nb0
		 * "Upgraded a resync read to an app read"
		 * so (rw == READ) for some reason ...
		 */
		// if (rw == READ)
		WARN("%s make_request(cmd=%s,sec=0x%04lx,size=0x%x)\n",
		     current->comm,
		     strs[rw],bh->b_rsector,bh->b_size);

	}
#endif

	if( mdev->lo_device == 0 ) {
		if( mdev->cstate < Connected ) {
			bh->b_end_io(bh,0);
			return 0;
		}

		if(!test_and_set_bit(WRITE_HINT_QUEUED,&mdev->flags)) {
			queue_task(&mdev->write_hint_tq, &tq_disk); // IO HINT
		}

		// Fail READA ??
		if( rw == WRITE ) {
			req = mempool_alloc(drbd_request_mempool, GFP_DRBD);

			if (!req) {
				ERR("could not kmalloc() req\n");
				bh->b_end_io(bh,0);
				return 0;
			}
			SET_MAGIC(req);

			req->rq_status = RQ_DRBD_WRITTEN | 1;
			req->bh=bh;

			if(mdev->conf.wire_protocol != DRBD_PROT_A) {
				inc_pending(mdev);
			}
			drbd_send_dblock(mdev,req); // FIXME error check?
		} else { // rw == READ || rw == READA
			drbd_issue_drequest(mdev,bh);
		}
		return 0; // Ok everything arranged
	}

	if( mdev->cstate == SyncTarget &&
	    bm_get_bit(mdev->mbds_id,bh->b_rsector,bh->b_size) ) {
		struct Pending_read *pr;
		if( rw == WRITE ) {
			spin_lock(&mdev->pr_lock);
			pr=drbd_find_read(bh->b_rsector,&mdev->resync_reads);

			if(pr) {
				ERR("Will discard a resync_read\n");
				pr->cause = Discard;
				// list del as well ?
			}
			spin_unlock(&mdev->pr_lock);

			// TODO wait until writes of syncer are done.
			// Continue with a mirrored write op.
			// Set some flag to clear it in the bitmap
		} else { // rw == READ || rw == READA
			spin_lock(&mdev->pr_lock);
			pr=drbd_find_read(bh->b_rsector,&mdev->resync_reads);
			if(pr) {
				ERR("Upgraded a resync read to an app read\n");

				pr->cause |= Application;
				pr->d.bh=bh;
				list_del(&pr->list);
				list_add(&pr->list,&mdev->app_reads);
				spin_unlock(&mdev->pr_lock);
				return 0; // Ok everything arranged
			}

			spin_unlock(&mdev->pr_lock);
			drbd_issue_drequest(mdev,bh);
			return 0;
		}
	}

	if( rw == READ || rw == READA ) {
		mdev->read_cnt+=bh->b_size>>9;

		bh->b_rdev = mdev->lo_device;
		return 1; // Not arranged for transfer ( but remapped :)
	}

	mdev->writ_cnt+=bh->b_size>>9;

	if(mdev->cstate<Connected || test_bit(PARTNER_DISKLESS,&mdev->flags)) {
		drbd_set_out_of_sync(mdev,bh->b_rsector,bh->b_size);

		drbd_al_begin_io(mdev, bh->b_rsector);
		drbd_al_complete_io(mdev, bh->b_rsector); // FIXME TODO 
		bh->b_rdev = mdev->lo_device;
		return 1; // Not arranged for transfer ( but remapped :)
	}

	// Now its clear that we have to do a mirrored write:

	req = mempool_alloc(drbd_request_mempool, GFP_DRBD);

	if (!req) {
		ERR("could not kmalloc() nbh\n");
		bh->b_end_io(bh,0);
		return 0;
	}
	SET_MAGIC(req);

	nbh = kmem_cache_alloc(bh_cachep, GFP_DRBD);

	drbd_init_bh(nbh, bh->b_size);

	nbh->b_page=bh->b_page; // instead of set_bh_page()
	nbh->b_data=bh->b_data; // instead of set_bh_page()

	drbd_set_bh(mdev, nbh, bh->b_rsector, bh->b_size);

	if(mdev->cstate < StandAlone || MINOR(bh->b_rdev) >= minor_count) {
		buffer_IO_error(bh);
		return 0;
	}

	nbh->b_private = req;
	nbh->b_state = (1 << BH_Dirty) | ( 1 << BH_Mapped) | (1 << BH_Lock);

	req->bh=bh;

	req->rq_status = RQ_DRBD_NOTHING;

	spin_lock_irq(&mdev->bb_lock);
	mdev->send_sector=bh->b_rsector;
	if( ds_check_sector(mdev,bh->b_rsector) ) {
		struct busy_block bl;
		bb_wait_prepare(mdev,bh->b_rsector,&bl);
		spin_unlock_irq(&mdev->bb_lock);
		bb_wait(&bl);
	} else spin_unlock_irq(&mdev->bb_lock);

	send_ok=drbd_send_dblock(mdev,req);
	// FIXME we could remove the send_ok cases, the are redundant to tl_clear()
	mdev->send_sector=-1;
	if(send_ok && mdev->conf.wire_protocol!=DRBD_PROT_A) inc_pending(mdev);
	if(mdev->conf.wire_protocol==DRBD_PROT_A || (!send_ok) ) {
				/* If sending failed, we can not expect
				   an ack packet. */
		drbd_end_req(req, RQ_DRBD_SENT, 1);
	}
	if(!send_ok) drbd_set_out_of_sync(mdev,bh->b_rsector,bh->b_size);

	if(!test_and_set_bit(WRITE_HINT_QUEUED,&mdev->flags)) {
		queue_task(&mdev->write_hint_tq, &tq_disk);
	}

	drbd_al_begin_io(mdev, nbh->b_rsector);

	nbh->b_end_io = drbd_dio_end;
	generic_make_request(rw,nbh);

	return 0; /* Ok, bh arranged for transfer */

}

