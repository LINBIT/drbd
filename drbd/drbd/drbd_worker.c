/*
-*- linux-c -*-
   drbd_dsender.c
   Kernel module for 2.2.x/2.4.x Kernels

   This file is part of drbd by Philipp Reisner.

   Copyright (C) 1999-2003, Philipp Reisner <philipp.reisner@gmx.at>.
	main author.

   Copyright 2003 Lars Ellenberg <l.g.e@web.de>
       contributions.

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

	mdev=bh->b_private;
	PARANOIA_BUG_ON(!IS_VALID_MDEV(mdev));

	e = container_of(bh,struct Tl_epoch_entry,pbh);
	PARANOIA_BUG_ON(!VALID_POINTER(e));
	D_ASSERT(e->block_id != ID_VACANT);

	spin_lock_irqsave(&mdev->ee_lock,flags);

	mark_buffer_uptodate(bh, uptodate);
	clear_bit(BH_Lock, &bh->b_state);
	smp_mb__after_clear_bit();

	list_del(&e->w.list);
	list_add(&e->w.list,&mdev->rdone_ee);

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
		e = list_entry(le, struct Tl_epoch_entry,w.list);
		spin_unlock_irq(&mdev->ee_lock);
		ok = ok && e->w.cb(mdev,&e->w);

		spin_lock_irq(&mdev->ee_lock);
		list_del(le);         // remove from list first.

		drbd_put_ee(mdev,e);
	}

	wake_up_interruptible(&mdev->ee_wait);

	return ok;
}

STATIC drbd_dev *ds_find_osg(drbd_dev *mdev)
{
	drbd_dev *odev;
	int i;

	for (i=0; i < minor_count; i++) {
		odev = drbd_conf + i;
		if ( odev->sync_conf.group < mdev->sync_conf.group
		     && odev->cstate > Connected ) {
			return odev;
		}
	}

	return 0;
}

STATIC int _ds_wait_osg(drbd_dev* odev, struct drbd_hook* dh)
{
	// This is a callback, I better not assume that this 
	// is a context which allows to send something from.
	unsigned long flags;
	drbd_dev *mdev = (drbd_dev*) dh->data;
	int added=0;

	if(odev->cstate <= Connected) {
	retry:
		if( (odev = ds_find_osg(mdev)) ) {
			spin_lock_irqsave(&odev->req_lock,flags);
			if(odev->cstate > Connected) {
				list_add_tail(&dh->list,&odev->cstate_hook);
				added=1;
			}
			spin_unlock_irqrestore(&odev->req_lock,flags);
			if(!added) goto retry;
		} else {
			set_bit(SYNC_CONTINUE,&mdev->flags);
			wake_up_interruptible(&mdev->dsender_wait);
			kfree(dh);
		}
		return 0; // do not add to this hook again.
	}
	return 1; // run again. 
}

STATIC int drbd_wait_for_other_sync_groups(drbd_dev *mdev)
{
	drbd_dev *odev;
	struct drbd_hook *dh=NULL;
	int added=0;

 retry:
	odev = ds_find_osg(mdev);
	if(!odev) return FALSE;

	while( dh == NULL ) {
		dh=kmalloc(sizeof(struct drbd_hook),GFP_KERNEL);
		if(dh) break;
		ERR("could not kmalloc drbd_hook\n");
		current->state = TASK_INTERRUPTIBLE;
		schedule_timeout(HZ);
	}

	dh->data = mdev;
	dh->callback = _ds_wait_osg;

	spin_lock_irq(&odev->req_lock);
	if(odev->cstate > Connected) {
		list_add_tail(&dh->list,&odev->cstate_hook);
		added=1;
	}
	spin_unlock_irq(&odev->req_lock);
	if(!added) goto retry;

	INFO("Syncer waits for sync group %i\n",
	     odev->sync_conf.group);
	drbd_send_short_cmd(mdev,SyncStop);
	set_cstate(mdev,PausedSyncT);

	return TRUE;
}

/* bool */
STATIC int ds_issue_requests(struct Drbd_Conf* mdev)
{
	int number,i;
	sector_t sector;

#define SLEEP_TIME (HZ/10)

	number = SLEEP_TIME*mdev->sync_conf.rate / ((BM_BLOCK_SIZE/1024)*HZ);

	// Remove later
	if(number > 1000) number=1000;
	if(atomic_read(&mdev->pending_cnt)>1200) {
		ERR("pending cnt high -- throttling resync.\n");
		return TRUE;
	}
	// /Remove later

	if(drbd_wait_for_other_sync_groups(mdev)) return FALSE;

	for(i=0;i<number;i++) {
		struct Pending_read *pr;
		int size=BM_BLOCK_SIZE;

		pr = mempool_alloc(drbd_pr_mempool, GFP_USER);
		if (!pr) return TRUE;
		SET_MAGIC(pr);

		sector = bm_get_sector(mdev->mbds_id,&size);

		if(sector == MBDS_DONE) {
			Drbd_Header h;
			INVALIDATE_MAGIC(pr);
			mempool_free(pr,drbd_pr_mempool);
			drbd_send_cmd(mdev,mdev->sock,WriteHint,&h,sizeof(h));
			return FALSE;
		}

		pr->d.sector = sector;
		pr->cause = Resync;
		spin_lock(&mdev->pr_lock);
		list_add(&pr->w.list,&mdev->resync_reads);
		spin_unlock(&mdev->pr_lock);

		inc_pending(mdev);
		ERR_IF(!drbd_send_drequest(mdev,RSDataRequest,
					  sector,size,(unsigned long)pr))
			dec_pending(mdev,HERE);
	}

	return TRUE;
}

void drbd_start_resync(struct Drbd_Conf *mdev, Drbd_CState side)
{
	set_cstate(mdev,side);
	mdev->rs_left=mdev->rs_total;
	mdev->rs_start=jiffies;
	mdev->rs_mark_left=mdev->rs_left;
	mdev->rs_mark_time=mdev->rs_start;

	INFO("Resync started as %s (need to sync %lu KB).\n",
	     side == SyncTarget ? "target" : "source", mdev->rs_left/2);

	if(side == SyncTarget) {
		set_bit(START_SYNC,&mdev->flags);
		// FIXME do this more elegant ...
		// for now, this ensures that meta data is "consistent"
		if ( mdev->rs_total == 0 ) set_bit(SYNC_FINISHED,&mdev->flags);
		wake_up_interruptible(&mdev->dsender_wait);
	} else {
		// If we are SyncSource we must be consistent :)
		mdev->gen_cnt[Flags] |= MDF_Consistent;
		if ( mdev->rs_total == 0 ) set_cstate(mdev,Connected);
	}
}

static inline int _dsender_cond(struct Drbd_Conf *mdev)
{
	int rv;
	rv = test_bit(START_SYNC,&mdev->flags) // TODO Use Lars' style _FLAG 
		|| test_bit(SYNC_FINISHED,&mdev->flags)
		|| test_bit(SYNC_CONTINUE,&mdev->flags);

	spin_lock_irq(&mdev->ee_lock);
	rv |= !list_empty(&mdev->rdone_ee);
	spin_unlock_irq(&mdev->ee_lock);

	return rv;
}

int drbd_dsender(struct Drbd_thread *thi)
{
	long time=MAX_SCHEDULE_TIMEOUT;
	drbd_dev *mdev = thi->mdev;

	sprintf(current->comm, "drbd%d_dsender", (int)(mdev-drbd_conf));

	while( thi->t_state == Running ) {

		wait_event_interruptible_timeout(
			mdev->dsender_wait,_dsender_cond(mdev),time);

		spin_lock_irq(&mdev->ee_lock);
		drbd_process_rdone_ee(mdev);
		spin_unlock_irq(&mdev->ee_lock);

		if(test_and_clear_bit(START_SYNC,&mdev->flags)) {
			time=SLEEP_TIME;
			mdev->gen_cnt[Flags] &= ~MDF_Consistent;
			drbd_md_write(mdev);
			bm_reset(mdev->mbds_id);
		}

		if(test_and_clear_bit(SYNC_FINISHED,&mdev->flags)) {
			unsigned long dt;
			dt = (jiffies - mdev->rs_start) / HZ + 1;
			INFO("Resync done (total %lu sec; %lu K/sec)\n",
			     dt,(mdev->rs_total/2)/dt);

			if(mdev->cstate == SyncTarget) {
				mdev->gen_cnt[Flags] |= MDF_Consistent;
				drbd_md_write(mdev);
			}
			mdev->rs_total = 0;
			set_cstate(mdev,Connected);

			// assert that all bit-map parts are cleared.
			D_ASSERT(list_empty(&mdev->resync->lru));
		}

		if(test_and_clear_bit(SYNC_CONTINUE,&mdev->flags) && 
		   (mdev->cstate == PausedSyncT) ) {
			time=SLEEP_TIME;
			INFO("resumed synchronisation.\n");
			drbd_send_short_cmd(mdev,SyncCont);
			set_cstate(mdev,SyncTarget);
		}

		if(time == SLEEP_TIME) {
			if (!ds_issue_requests(mdev)) {
				time=MAX_SCHEDULE_TIMEOUT;
			}
			if (!disable_io_hints) {
				Drbd_Header h;
				drbd_send_cmd(mdev,mdev->sock,WriteHint,&h,
					      sizeof(h));
			}
		}
	}

	return 0;
}

