/*
-*- linux-c -*-
   drbd_dsender.c
   Kernel module for 2.2.x/2.4.x Kernels

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

#include <asm/bitops.h>
#include <linux/sched.h>
#include <linux/smp_lock.h>
#include <linux/wait.h>
#define __KERNEL_SYSCALLS__
#include <linux/slab.h>

#include "drbd.h"
#include "drbd_int.h"

void drbd_dio_end_read(struct buffer_head *bh, int uptodate)
{
	/* This callback will be called in irq context by the IDE drivers,
	   and in Softirqs/Tasklets/BH context by the SCSI drivers.
	   Try to get the locking right :) */
	unsigned long flags=0;
	struct Tl_epoch_entry *e=NULL;
	struct Drbd_Conf* mdev;

	mdev=drbd_lldev_to_mdev(bh->b_dev);

	e=bh->b_private;
	spin_lock_irqsave(&mdev->ee_lock,flags);

	mark_buffer_uptodate(bh, uptodate);
	clear_bit(BH_Lock, &bh->b_state);

	/* Do not move a BH if someone is in wait_on_buffer */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,3,0)
	if(bh->b_count == 0)
#else
	if(atomic_read(&bh->b_count) == 0)
#endif
	{
		list_del(&e->list);
		list_add(&e->list,&mdev->rdone_ee);
	}

	if (waitqueue_active(&bh->b_wait))
		wake_up(&bh->b_wait);

	spin_unlock_irqrestore(&mdev->ee_lock,flags);

	wake_up_interruptible(&mdev->dsender_wait);
}

int drbd_process_rdone_ee(struct Drbd_Conf* mdev)
{
	struct Tl_epoch_entry *e;
	struct list_head *le;
	int ok=1;

	MUST_HOLD(&mdev->ee_lock);

	while(!list_empty(&mdev->rdone_ee)) {
		le = mdev->rdone_ee.next;
		e = list_entry(le, struct Tl_epoch_entry,list);
		spin_unlock_irq(&mdev->ee_lock);
		ok = ok && e->e_end_io(mdev,e);

		spin_lock_irq(&mdev->bb_lock); 
		spin_lock(&mdev->ee_lock); // first bb_lock then ee_lock
		list_del(le);         // remove from list first.
		bb_done(mdev,e->bh->b_blocknr);  // signal completion second.
		spin_unlock(&mdev->bb_lock);

		drbd_put_ee(mdev,e);
	}

	wake_up_interruptible(&mdev->ee_wait);

	return ok;
}


int ds_check_sector(struct Drbd_Conf *mdev, sector_t sector)
{
	/* When intoducing active/active this must also consider pending read
	   requests. (currently only unacked requests are considered.) */
	/* This function is called with IRQs disabled (and bb_lock locked)
	   therefore no spin_lock_irq */
	struct Tl_epoch_entry *e;
	struct list_head *le;
	int rv=FALSE;

	spin_lock(&mdev->ee_lock);

	list_for_each(le,&mdev->read_ee) {
		e = list_entry(le, struct Tl_epoch_entry,list);
		if(BH_SECTOR(e->bh) == sector) {
			rv=TRUE;
			goto out;
		}
	}

	list_for_each(le,&mdev->rdone_ee) {
		e = list_entry(le, struct Tl_epoch_entry,list);
		if(BH_SECTOR(e->bh) == sector) {
			rv=TRUE;
			goto out;
		}
	}

 out:
	spin_unlock(&mdev->ee_lock);
	return rv;
}

STATIC int ds_issue_requests(struct Drbd_Conf* mdev)
{
	int number,i;
	sector_t sector;

#define SLEEP_TIME 10

	number = SLEEP_TIME*mdev->sync_conf.rate / ((BM_BLOCK_SIZE/1024)*HZ);

	// Remove later
	if(number > 1000) number=1000;	
	if(atomic_read(&mdev->pending_cnt)>1200) {
		printk(KERN_ERR DEVICE_NAME 
		       "%d: pending cnt high -- throttling resync.\n",
		       (int)(mdev-drbd_conf));
		return TRUE;
	}
	// /Remove later

	for(i=0;i<number;i++) {
		struct Pending_read *pr;
		int size=BM_BLOCK_SIZE;
	
		pr = kmalloc(sizeof(struct Pending_read), GFP_USER );
		if (!pr) return TRUE;

		sector = bm_get_sector(mdev->mbds_id,&size);
		if(sector == MBDS_DONE) {
			kfree(pr);
			return FALSE;
		}

		pr->d.sector = sector;
		pr->cause = Resync;
		spin_lock(&mdev->pr_lock);
		list_add(&pr->list,&mdev->resync_reads);
		spin_unlock(&mdev->pr_lock);

		if(drbd_send_drequest(mdev,RSDataRequest,sector,size,
				      (unsigned long)pr))
			inc_pending(mdev);
	}

	return TRUE;
}

void drbd_start_resync(struct Drbd_Conf *mdev, Drbd_CState side) 
{
	/*printk(KERN_ERR DEVICE_NAME "%d: rs_total=%lu\n",
	  (int)(mdev-drbd_conf),mdev->rs_total);*/

	set_cstate(mdev,side);
	mdev->rs_left=mdev->rs_total;
	mdev->rs_start=jiffies;
	mdev->rs_mark_left=mdev->rs_left;
	mdev->rs_mark_time=mdev->rs_start;

	if(side == SyncTarget) {
		spin_lock_irq(&mdev->ee_lock); // (ab)use ee_lock see, below.
		set_bit(START_SYNC,&mdev->flags);
		spin_unlock_irq(&mdev->ee_lock);
                wake_up_interruptible(&mdev->dsender_wait);
	}
}

int drbd_dsender(struct Drbd_thread *thi)
{
	struct Drbd_Conf *mdev=drbd_conf+thi->minor;
	long time=MAX_SCHEDULE_TIMEOUT;
	wait_queue_t wait;
	int start_sync;
	int sync_finished;

	sprintf(current->comm, "drbd_dsender_%d", (int)(mdev-drbd_conf));

	while(1) {
		init_waitqueue_entry(&wait, current);

		/*
		spin_lock_irq(&mdev->ee_lock);
		drbd_process_rdone_ee(mdev);
		spin_unlock_irq(&mdev->ee_lock);
		interruptible_sleep_on_timeout(&mdev->dsender_wait,time);

		   The naive methode has the drawback, that the wakeup
		   could happen before we are in sleep_on_timeout(), therefore
		*/

		spin_lock_irq(&mdev->ee_lock);
		drbd_process_rdone_ee(mdev);
		
		current->state = TASK_INTERRUPTIBLE;
		spin_lock(&mdev->dsender_wait.lock);
		__add_wait_queue(&mdev->dsender_wait, &wait);
		spin_unlock(&mdev->dsender_wait.lock);

		start_sync=test_and_clear_bit(START_SYNC,&mdev->flags);
		sync_finished=test_and_clear_bit(SYNC_FINISHED,&mdev->flags);

		spin_unlock_irq(&mdev->ee_lock);

		if(start_sync) { 
			time=SLEEP_TIME;
			mdev->gen_cnt[Flags] &= ~MDF_Consistent;
			drbd_md_write(mdev);
			bm_reset(mdev->mbds_id);
			printk(KERN_INFO DEVICE_NAME "%d: resync started.\n",
			       (int)(mdev-drbd_conf));
		}

		if(sync_finished) {
			printk(KERN_INFO DEVICE_NAME "%d: resync done.\n",
			       (int)(mdev-drbd_conf));
			if(mdev->cstate == SyncTarget) {
				mdev->gen_cnt[Flags] |= MDF_Consistent;
				drbd_md_write(mdev);
			}
			mdev->rs_total = 0;
			set_cstate(mdev,Connected);
		}

		schedule_timeout(time);

		spin_lock_irq(&mdev->dsender_wait.lock);
		__remove_wait_queue(&mdev->dsender_wait, &wait);
		spin_unlock_irq(&mdev->dsender_wait.lock);

		if (thi->t_state == Exiting) break;
		  		
		if(time==SLEEP_TIME) {
			spin_lock_irq(&mdev->ee_lock);
			drbd_process_rdone_ee(mdev); // Why again ?
			spin_unlock_irq(&mdev->ee_lock);
			if(!ds_issue_requests(mdev)) {
				time=MAX_SCHEDULE_TIMEOUT;
				mdev->rs_total=mdev->rs_left;
			}
			drbd_send_cmd(mdev,WriteHint,0); // IO hint 
		} 
		
	}

	return 0;
}

