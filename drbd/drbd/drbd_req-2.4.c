/*
-*- linux-c -*-
   drbd.c
   Kernel module for 2.2.x/2.4.x Kernels

   This file is part of drbd by Philipp Reisner.

   Copyright (C) 1999-2001, Philipp Reisner <philipp.reisner@gmx.at>.
        main author.

   Copyright (C) 2000, Marcelo Tosatti <marcelo@conectiva.com.br>.
        Added code for Linux 2.3.x

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

void drbd_end_req(drbd_request_t *req, int nextstate, int uptodate)
{
	int wake_asender=0;
	unsigned long flags=0;
	struct Drbd_Conf* mdev = drbd_conf + MINOR(req->bh->b_rdev);

/*
      	printk(KERN_ERR DEVICE_NAME "%d: drbd_end_req(%p,%x)\n",
	       (int)(mdev-drbd_conf),req,nextstate);	
*/

	if (req->rq_status == (RQ_DRBD_READ | 0x0001))
		goto end_it_unlocked;

	/* This was a hard one! Can you see the race?
	   (It hit me about once out of 20000 blocks) 

	   switch(status) {
	   ..: status = ...;
	   }
	*/

	spin_lock_irqsave(&mdev->req_lock,flags);

	switch (req->rq_status & 0xfffe) {
	case RQ_DRBD_SEC_WRITE:
	        wake_asender=1;
		goto end_it;
	case RQ_DRBD_NOTHING:
		req->rq_status = nextstate | (uptodate ? 1 : 0);
		break;
	case RQ_DRBD_SENT:
		if (nextstate == RQ_DRBD_WRITTEN)
			goto end_it;
		printk(KERN_ERR DEVICE_NAME "%d: request state error(A)\n",
		       (int)(mdev-drbd_conf));
		break;
	case RQ_DRBD_WRITTEN:
		if (nextstate == RQ_DRBD_SENT)
			goto end_it;
		printk(KERN_ERR DEVICE_NAME "%d: request state error(B)\n",
		       (int)(mdev-drbd_conf));
		break;
	default:
		printk(KERN_ERR DEVICE_NAME "%d: request state error(%X)\n",
		       (int)(mdev-drbd_conf),req->rq_status);
	}

	spin_unlock_irqrestore(&mdev->req_lock,flags);

	return;

/* We only report uptodate == TRUE if both operations (WRITE && SEND)
   reported uptodate == TRUE 
 */

	end_it:
	spin_unlock_irqrestore(&mdev->req_lock,flags);

	end_it_unlocked:

	if(mdev->state == Primary && mdev->cstate >= Connected) {
	  /* If we are unconnected we may not call tl_dependece, since
	     then this call could be from tl_clear(). => spinlock deadlock!
	  */
	        if(tl_dependence(mdev,req)) {
	                set_bit(ISSUE_BARRIER,&mdev->flags);
			wake_asender=1;
		}
	}

	if(mdev->state == Secondary) {
		struct Tl_epoch_entry *e;
		e=req->bh->b_private;
		if( e ) {
			spin_lock_irqsave(&mdev->ee_lock,flags);
			list_del(&e->list);
			list_add(&e->list,&mdev->done_ee);
			spin_unlock_irqrestore(&mdev->ee_lock,flags);
		} else {
			printk(KERN_ERR DEVICE_NAME "%d: e == NULL "
			       ", bh=%p\n",
			       (int)(mdev-drbd_conf),req->bh);
		} 
	}

	req->bh->b_end_io(req->bh,uptodate & req->rq_status);

	if( mdev->do_panic && !(uptodate & req->rq_status) ) {
		panic(DEVICE_NAME": The lower-level device had an error.\n");
	}

	kfree(req); /* frees also the temporary bh */

	/* NICE: It would be nice if we could AND this condition.
	   But we must also wake the asender if we are receiving 
	   syncer blocks! */
	if(wake_asender /*&& mdev->conf.wire_protocol == DRBD_PROT_C*/ ) {
	        wake_up_interruptible(&mdev->asender_wait);
	}
}

void drbd_dio_end(struct buffer_head *bh, int uptodate)
{
	drbd_request_t *req;

	req = bh->b_private;

	// READs are sorted out in drbd_end_req().
	drbd_end_req(req, RQ_DRBD_WRITTEN, uptodate);
}

int drbd_make_request(request_queue_t *q, int rw, struct buffer_head *bh)
{
	struct Drbd_Conf* mdev = drbd_conf + MINOR(bh->b_rdev);
	struct buffer_head *nbh;
	drbd_request_t *req;
	int cbs = 1 << mdev->blk_size_b;
	int size_kb;

	if (bh->b_size != cbs) {
		/* If someone called set_blocksize() from fs/buffer.c ... */

		cbs = bh->b_size;
		set_blocksize(mdev->lo_device,cbs);
		mdev->blk_size_b = drbd_log2(cbs);

		printk(KERN_INFO DEVICE_NAME "%d: blksize=%d B\n",
		       (int)(mdev-drbd_conf),cbs);
	}

	size_kb = 1<<(mdev->blk_size_b-10);

	/* Do disk - IO */
	req = kmalloc(sizeof(struct buffer_head)+
		      sizeof(drbd_request_t), GFP_DRBD);
	if (!req) {
		printk(KERN_ERR DEVICE_NAME
		       "%d: could not kmalloc() nbh\n",(int)(mdev-drbd_conf));
		bh->b_end_io(bh,0);
		return 0;
	}

	nbh = (struct buffer_head*)(((char*)req)+sizeof(drbd_request_t));

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

	
	memset(nbh, 0, sizeof(*nbh));
	nbh->b_blocknr=bh->b_blocknr;
	nbh->b_size=bh->b_size;
	nbh->b_data=bh->b_data;
	nbh->b_list = BUF_LOCKED;
	nbh->b_end_io = drbd_dio_end;
	nbh->b_dev = mdev->lo_device;
	nbh->b_rdev = mdev->lo_device;
	nbh->b_rsector = bh->b_rsector;          
	nbh->b_page=bh->b_page;
	atomic_set(&nbh->b_count, 0);
	nbh->b_private = req;
	nbh->b_state = (1 << BH_Req) | (1 << BH_Dirty)
		| ( 1 << BH_Mapped) | (1 << BH_Lock);

	req->bh=bh;

	switch(rw) {
	case READ:
	case READA:
		mdev->read_cnt+=size_kb; 
		req->rq_status = RQ_DRBD_READ | 0x0001;
		break;
	case WRITE:
		mdev->writ_cnt+=size_kb;
		
		if (mdev->state == Primary) {
			if ( mdev->cstate >= Connected
			     && bh->b_rsector >= mdev->synced_to) {

			int bnr = bh->b_rsector >> (mdev->blk_size_b - 9);
			int send_ok;
     		        send_ok=drbd_send_data(mdev, bh->b_data,
					   cbs,bnr,(unsigned long)req);

			if(send_ok) {
				mdev->send_cnt+=size_kb;
			}

			if( mdev->conf.wire_protocol==DRBD_PROT_A ||
			    (!send_ok) ) {
				/* If sending failed, we can not expect
				   an ack packet. */
			         drbd_end_req(req, RQ_DRBD_SENT, 1);
			}

			req->rq_status = RQ_DRBD_NOTHING;
			} else {
				bm_set_bit(mdev->mbds_id,
					   bh->b_rsector >> 
					   (mdev->blk_size_b-9),
					   mdev->blk_size_b, 
					   SS_OUT_OF_SYNC);
				req->rq_status = RQ_DRBD_SENT | 0x0001;
			}
		} else {
			req->rq_status = RQ_DRBD_SEC_WRITE | 0x0001;
		}
		break;
	default:
		bh->b_end_io(bh,0); /* should not happen*/
		return 0;
	}

	generic_make_request(rw,nbh);

	return 0; /* Ok, bh arranged for transfer */
}


