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

void enslaved_read_bh_end_io(struct buffer_head *bh, int uptodate)
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
	spin_unlock_irqrestore(&mdev->ee_lock,flags);

	drbd_queue_work(mdev,&mdev->data.work,&e->w);
}

int w_resync_inactive(drbd_dev *mdev, struct drbd_work *w)
{
	ERR("resync inactive, but callback triggered??\n");
	return 0;
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

void resync_timer_fn(unsigned long data)
{
	drbd_dev* mdev;

	mdev = (drbd_dev*) data;

	drbd_queue_work(mdev,&mdev->data.work,&mdev->resync_work);
}

STATIC int w_make_resync_request(drbd_dev* mdev, struct drbd_work* w)
{
	struct Pending_read *pr;
	struct Drbd_Conf    *odev;
	sector_t sector;
	int number,i,size;

	PARANOIA_BUG_ON(w != &mdev->resync_work);

	// wait_for_other_sync_groups
	odev = ds_find_osg(mdev);
	if (odev) {
		spin_lock_irq(&odev->req_lock);
		if (odev->cstate > Connected) {
			list_add_tail(&w->list,&odev->cstate_hook);
			spin_unlock_irq(&odev->req_lock);
			INFO("Syncer waits for sync group %i\n",
			     odev->sync_conf.group);
			drbd_send_short_cmd(mdev,SyncStop);
			set_cstate(mdev,PausedSyncT);
			return 1;
		}
		// state change while we were looking at it. never mind ...
		spin_unlock_irq(&odev->req_lock);
	}

	if (mdev->cstate == PausedSyncT) {
		INFO("resumed synchronisation.\n");
		drbd_send_short_cmd(mdev,SyncCont);
		set_cstate(mdev,SyncTarget);
	}
	D_ASSERT(mdev->cstate == SyncTarget);

#define SLEEP_TIME (HZ/10)

        number = SLEEP_TIME*mdev->sync_conf.rate / ((BM_BLOCK_SIZE/1024)*HZ);

        if(number > 1000) number=1000;  // Remove later
	if (atomic_read(&mdev->pending_cnt)>1200) {
		// INFO("pending cnt high -- throttling resync.\n");
		goto requeue;
	}

	for(i=0;i<number;i++) {
		pr = mempool_alloc(drbd_pr_mempool, GFP_USER);
		if (unlikely(pr == NULL)) goto requeue;
		SET_MAGIC(pr);
		
		size = BM_BLOCK_SIZE;
		sector = bm_get_sector(mdev->mbds_id,&size);

		if (sector == MBDS_DONE) {
			INVALIDATE_MAGIC(pr);
			mempool_free(pr,drbd_pr_mempool);
			mdev->resync_work.cb = w_resync_inactive;
			return 1;
		}

		pr->d.sector = sector;
		pr->cause = Resync;
		spin_lock(&mdev->pr_lock);
		list_add(&pr->w.list,&mdev->resync_reads);
		spin_unlock(&mdev->pr_lock);

		inc_pending(mdev);
		ERR_IF(!drbd_send_drequest(mdev,RSDataRequest,
					   sector,size,(unsigned long)pr)) {
			dec_pending(mdev,HERE);
			return 0; // FAILED. worker will abort!
		}
	}

   requeue:
	mdev->resync_timer.expires = jiffies + SLEEP_TIME;
	add_timer(&mdev->resync_timer);
	return 1;
}

int w_resync_finished(drbd_dev* mdev, struct drbd_work* w)
{
	unsigned long dt;

	PARANOIA_BUG_ON(w != &mdev->resync_work);
	D_ASSERT(mdev->rs_left == 0);

	dt = (jiffies - mdev->rs_start) / HZ + 1;
	INFO("Resync done (total %lu sec; %lu K/sec)\n",
	     dt,(mdev->rs_total/2)/dt);

	if (mdev->cstate == SyncTarget) {
		mdev->gen_cnt[Flags] |= MDF_Consistent;
		drbd_md_write(mdev);
	}
	mdev->rs_total = 0;
	set_cstate(mdev,Connected);

	// assert that all bit-map parts are cleared.
	D_ASSERT(list_empty(&mdev->resync->lru));
	w->cb = w_resync_inactive;
	INIT_LIST_HEAD(&w->list);
	return 1;
}

int w_e_end_data_req(drbd_dev *mdev, struct drbd_work *w)
{
	struct Tl_epoch_entry *e = (struct Tl_epoch_entry*)w;
	int ok;

	ok=drbd_send_block(mdev, DataReply, e);
	dec_unacked(mdev,HERE); // THINK unconditional?

	spin_lock_irq(&mdev->ee_lock);
	drbd_put_ee(mdev,e);
	spin_unlock_irq(&mdev->ee_lock);

	if(unlikely(!ok)) ERR("drbd_send_block() failed\n");
	return ok;
}

int w_e_end_rsdata_req(drbd_dev *mdev, struct drbd_work *w)
{
	struct Tl_epoch_entry *e = (struct Tl_epoch_entry*)w;
	int ok;

	drbd_rs_complete_io(mdev,DRBD_BH_SECTOR(&e->pbh));
	inc_pending(mdev);
	ok=drbd_send_block(mdev, DataReply, e);
	dec_unacked(mdev,HERE); // THINK unconditional?

	spin_lock_irq(&mdev->ee_lock);
	drbd_put_ee(mdev,e);
	spin_unlock_irq(&mdev->ee_lock);

	if(unlikely(!ok)) ERR("drbd_send_block() failed\n");
	return ok;
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

	PARANOIA_BUG_ON(!list_empty(&mdev->resync_work.list));
	PARANOIA_BUG_ON(mdev->resync_work.cb != w_resync_inactive);

	if ( mdev->rs_left == 0 ) {
		mdev->resync_work.cb = w_resync_finished;
		drbd_queue_work(mdev,&mdev->data.work,&mdev->resync_work);
		return;
	}

	if(mdev->cstate == SyncTarget) {
		mdev->gen_cnt[Flags] &= ~MDF_Consistent;
		bm_reset(mdev->mbds_id);
		mdev->resync_work.cb = w_make_resync_request;
		drbd_queue_work(mdev,&mdev->data.work,&mdev->resync_work);
	} else {
		// If we are SyncSource we must be consistent :)
		mdev->gen_cnt[Flags] |= MDF_Consistent;
	}

	drbd_md_write(mdev);
}

int drbd_worker(struct Drbd_thread *thi)
{
	drbd_dev *mdev = thi->mdev;
	struct drbd_work *w;
	unsigned long flags;
	int intr;

	sprintf(current->comm, "drbd%d_worker", (int)(mdev-drbd_conf));

	mdev->resync_timer.function = resync_timer_fn;
	mdev->resync_timer.data = (unsigned long) mdev;
	
	for (;;) {
		intr = down_interruptible(&mdev->data.work.s);

		if (intr) {
			D_ASSERT(intr == -EINTR);
			LOCK_SIGMASK(current,flags);
			if (sigismember(&current->pending.signal, SIGTERM)) {
				sigdelset(&current->pending.signal, SIGTERM);
				RECALC_SIGPENDING(current);
			}
			UNLOCK_SIGMASK(current,flags);
			if (thi->t_state != Running )
				break;
			continue;
		}

		if (thi->t_state != Running )
			break;
		if (need_resched())
			schedule();

		w = NULL;
		spin_lock_irq(&mdev->req_lock);
		if (!list_empty(&mdev->data.work.q)) {
			w = list_entry(mdev->data.work.q.next,struct drbd_work,list);
			list_del(&w->list);
		}
		spin_unlock_irq(&mdev->req_lock);

		ERR_IF (!w)
			continue; // BUG()... racy up() somewhere ??

		ERR_IF ( !w->cb(mdev,w) )
			break;
	}

	INFO("worker terminated\n");

	return 0;
}
