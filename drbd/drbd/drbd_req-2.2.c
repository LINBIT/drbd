/*
-*- linux-c -*-
   drbd.c
   Kernel module for 2.2.x Kernels

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

void drbd_end_req(struct request *req, int nextstate, int uptodate)
{
	struct Drbd_Conf* mdev = &drbd_conf[MINOR(req->rq_dev)];
	int wake_asender=0;
	unsigned long flags=0;
	struct Tl_epoch_entry *e=NULL;


	if (req->cmd == READ)
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

	spin_lock_irqsave(&mdev->bb_lock,flags);
	bb_done(mdev,req->bh->b_blocknr);
	spin_unlock_irqrestore(&mdev->bb_lock,flags);

	if(mdev->state == Secondary) {
		e=req->bh->b_dev_id;
		// since read requests do not have the b_private field set
		if( e ) {
			spin_lock_irqsave(&mdev->ee_lock,flags);
			list_del(&e->list);
/*		} else {
			printk(KERN_ERR DEVICE_NAME "%d: e == NULL "
			       ", bh=%p\n",
			       (int)(mdev-drbd_conf),req->bh);
*/
		}
	}

	if(!end_that_request_first(req, uptodate & req->rq_status,DEVICE_NAME))
	        end_that_request_last(req);

	if(e) {
		list_add(&e->list,&mdev->done_ee);
		spin_unlock_irqrestore(&mdev->ee_lock,flags);
		if(mdev->conf.wire_protocol == DRBD_PROT_C ||
		   e->block_id == ID_SYNCER ) wake_asender=1;
	}

	if( mdev->do_panic && !(uptodate & req->rq_status) ) {
		panic(DEVICE_NAME": The lower-level device had an error.\n");
	}

	if(wake_asender) {
		drbd_queue_signal(DRBD_SIG, mdev->asender.task);
	}
}

void drbd_dio_end(struct buffer_head *bh, int uptodate)
{
        struct request *req = bh->b_dev_id;

	// READs are sorted out in drbd_end_req().
	drbd_end_req(req, RQ_DRBD_WRITTEN, uptodate);
	
	kfree(bh);
}

/*
  We should _nerver_ sleep with the io_request_lock aquired. (See ll_rw_block)
  Up to now I have considered these ways out:
  * 1) unlock the io_request_lock for the time of the send 
         Not possible, because I do not have the flags for the unlock.
           -> Forget the flags, look at the loop block device!!
  * 2) postpone the send to some point in time when the request lock
       is not hold. 
         Maybe using the tq_scheduler task queue, or an dedicated
         execution context (kernel thread).

         I am not sure if tq_schedule is a good idea, because we
         could send some process to sleep, which would not sleep
	 otherwise.
	   -> tq_schedule is a bad idea, sometimes sock_sendmsg
	      behaves *bad* ( return value does not indicate
	      an error, but ... )

  Non atomic things, that need to be done are:
  sock_sendmsg(), kmalloc(,GFP_KERNEL) and ll_rw_block().
*/

/*static */ void drbd_do_request()
{
	struct buffer_head *bh;
	int size_kb;
	int minor = 0;
	struct request *req;
	int sending;
	unsigned long flags;
	struct Drbd_Conf *mdev;

	minor = MINOR(CURRENT->rq_dev);
	size_kb=1<<(drbd_conf[minor].blk_size_b-10);
	mdev = &drbd_conf[minor];
	
	if (blksize_size[MAJOR_NR][minor] !=
	    (1 << drbd_conf[minor].blk_size_b)) {
		/* If someone called set_blocksize() from fs/buffer.c ... */
		int new_blksize;

		spin_unlock_irq(&io_request_lock);

		new_blksize = blksize_size[MAJOR_NR][minor];
		set_blocksize(drbd_conf[minor].lo_device, new_blksize);
		drbd_conf[minor].blk_size_b = drbd_log2(new_blksize);

		printk(KERN_INFO DEVICE_NAME "%d: blksize=%d B\n",
		       minor,new_blksize);

		spin_lock_irq(&io_request_lock);
	}
	while (TRUE) {
		INIT_REQUEST;
		req=CURRENT;
		CURRENT=req->next;
		
#if 0
		{
			static const char *strs[2] = 
			{
				"READ",
				"WRITE"
			};
			
			/* if(req->cmd == WRITE) */
			printk(KERN_ERR DEVICE_NAME "%d: do_request(cmd=%s,"
			       "sec=%ld,nr_sec=%ld,cnr_sec=%ld)\n",
			       minor,
			       strs[req->cmd == READ ? 0 : 1],req->sector,
			       req->nr_sectors,
			       req->current_nr_sectors);
		}
#endif

		spin_unlock_irq(&io_request_lock);

		sending = 0;

		if (req->cmd == WRITE && drbd_conf[minor].state == Primary) {
			if ( drbd_conf[minor].cstate >= Connected
			     && req->sector >= drbd_conf[minor].synced_to) {
				sending = 1;
			}
		}

		bh = kmalloc(sizeof(struct buffer_head), GFP_DRBD);
		if (!bh) {
			printk(KERN_ERR DEVICE_NAME
			       "%d: could not kmalloc()\n",minor);
			return;
		}

		drbd_init_bh(bh,
			     req->bh->b_size,
			     req->bh->b_data,
			     drbd_dio_end);

		drbd_set_bh(bh,
			    req->bh->b_rsector / (req->bh->b_size >> 9),
			    drbd_conf[minor].lo_device);

		bh->b_dev_id = req;
		bh->b_state = (1 << BH_Dirty);

		if(req->cmd == WRITE) 
			drbd_conf[minor].writ_cnt+=size_kb;
		else drbd_conf[minor].read_cnt+=size_kb;
		
		if (sending)
			req->rq_status = RQ_DRBD_NOTHING;
		else if (req->cmd == WRITE) {
			if(drbd_conf[minor].state == Secondary)
				req->rq_status = RQ_DRBD_SEC_WRITE | 0x0001;
			else {
				req->rq_status = RQ_DRBD_SENT | 0x0001;
				bm_set_bit(drbd_conf[minor].mbds_id,
					   req->sector >> 
					   (drbd_conf[minor].blk_size_b-9),
					   drbd_conf[minor].blk_size_b, 
					   SS_OUT_OF_SYNC);
			}
		} else req->rq_status = RQ_DRBD_READ | 0x0001;


		/* Send it out to the network */
		if (sending) {
			int bnr;
			int send_ok;
			bnr = req->sector >> (drbd_conf[minor].blk_size_b - 9);

			spin_lock_irqsave(&mdev->bb_lock,flags);
			mdev->send_block=bnr;
			if( ds_check_block(mdev,bnr) ) {
				bb_wait(mdev,bnr,&flags);
			}
			spin_unlock_irqrestore(&mdev->bb_lock,flags);

			send_ok=drbd_send_block(mdev,bh,(unsigned long)req);
			mdev->send_block=-1;

			if(send_ok) {
			        drbd_conf[minor].send_cnt+=
					req->current_nr_sectors<<1;
			}

			if( drbd_conf[minor].conf.wire_protocol==DRBD_PROT_A ||
			    (!send_ok) ) {
				/* If sending failed, we can not expect
				   an ack packet. */
			         drbd_end_req(req, RQ_DRBD_SENT, 1);
			}
				
		}

		ll_rw_block(req->cmd, 1, &bh);
		
		spin_lock_irq(&io_request_lock);
	}
}
