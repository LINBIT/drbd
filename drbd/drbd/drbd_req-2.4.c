/*
-*- linux-c -*-
   drbd.c
   Kernel module for 2.4.x Kernels

   This file is part of drbd by Philipp Reisner.

   Copyright (C) 1999-2001, Philipp Reisner <philipp.reisner@gmx.at>.
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
	int wake_asender=0;
	unsigned long flags=0;

	spin_lock_irqsave(&mdev->req_lock,flags);
	
	if(req->rq_status & nextstate) {
		printk(KERN_ERR DEVICE_NAME "%d: request state error(%d)\n",
		       (int)(mdev-drbd_conf),req->rq_status);		
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
		if(tl_dependence(mdev,req)) {
			set_bit(ISSUE_BARRIER,&mdev->flags);
			wake_asender=1;
		}
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

	if(wake_asender) {
		drbd_queue_signal(DRBD_SIG, mdev->asender.task);
	}
}

void drbd_dio_end(struct buffer_head *bh, int uptodate)
{
	drbd_request_t *req;

	req = bh->b_private;

	drbd_end_req(req, RQ_DRBD_WRITTEN, uptodate);
	// BIG TODO: Only set it, iff it is the case!
	drbd_set_in_sync(drbd_conf+MINOR(req->bh->b_rdev),
			 APP_BH_SECTOR(req->bh),
			 req->bh->b_size);

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
	pr = kmalloc(sizeof(struct Pending_read), GFP_DRBD);

	if (!pr) {
		printk(KERN_ERR DEVICE_NAME
		       "%d: could not kmalloc() pr\n",
		       (int)(mdev-drbd_conf));
		bh->b_end_io(bh,0);
		return;
	}

	pr->d.bh = bh;	
	pr->cause = mdev->cstate == SyncTarget ? AppAndResync : Application;
	spin_lock(&mdev->pr_lock);
	list_add(&pr->list,&mdev->app_reads);
	spin_unlock(&mdev->pr_lock);
	inc_pending(mdev);
	drbd_send_drequest(mdev,DataRequest, bh->b_rsector, bh->b_size,
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
		
		printk(KERN_ERR DEVICE_NAME "%d: make_request(cmd=%s,"
		       "sec=%ld, size=%d)\n",
		       (int)(mdev-drbd_conf),
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
			req = kmalloc(sizeof(drbd_request_t), GFP_DRBD);

			if (!req) {
				printk(KERN_ERR DEVICE_NAME
				       "%d: could not kmalloc() req\n",
				       (int)(mdev-drbd_conf));
				bh->b_end_io(bh,0);
				return 0;
			}

			req->rq_status = RQ_DRBD_WRITTEN | 1;
			req->bh=bh;

			if(mdev->conf.wire_protocol!=DRBD_PROT_A) {
				inc_pending(mdev);
			}
			drbd_send_dblock(mdev,bh,(unsigned long)req);
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
				printk(KERN_ERR DEVICE_NAME
				       "%d: Will discard a resync_read\n",
				       (int)(mdev-drbd_conf));

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
				printk(KERN_ERR DEVICE_NAME
				       "%d: Uprgraded a resync read to an "
				       "app read\n",
				       (int)(mdev-drbd_conf));

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

		bh->b_rdev = mdev->lo_device;
		return 1; // Not arranged for transfer ( but remapped :)
	}

	// Now its clear that we have to do a mirrored write:

	req = mempool_alloc(drbd_request_mempool, GFP_DRBD);

	if (!req) {
		printk(KERN_ERR DEVICE_NAME
		       "%d: could not kmalloc() nbh\n",(int)(mdev-drbd_conf));
		bh->b_end_io(bh,0);
		return 0;
	}

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

	send_ok=drbd_send_dblock(mdev,bh,(unsigned long)req);
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

	nbh->b_end_io = drbd_dio_end;
	generic_make_request(rw,nbh);
	
	return 0; /* Ok, bh arranged for transfer */

}

