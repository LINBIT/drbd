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

#include <linux/config.h>
#include <linux/module.h>

#include <asm/bitops.h>
#include <linux/sched.h>
#include <linux/smp_lock.h>
#include <linux/wait.h>
#define __KERNEL_SYSCALLS__
#include <linux/slab.h>

#include <linux/drbd.h>
#include "drbd_int.h"

/* I choose to have all block layer end_io handlers defined here.

 * For all these callbacks, note the follwing:
 * The callbacks will be called in irq context by the IDE drivers,
 * and in Softirqs/Tasklets/BH context by the SCSI drivers.
 * Try to get the locking right :)
 *
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)

/* used for synchronous meta data and bitmap IO
 * submitted by FIXME (I'd say worker only, but currently this is not true...)
 */
void drbd_md_io_complete(struct buffer_head *bh, int uptodate)
{
	if (uptodate)
		set_bit(BH_Uptodate, &bh->b_state);

	complete((struct completion*)bh->b_private);
}

/* reads on behalf of the partner,
 * "submitted" by the receiver
 */
void enslaved_read_bi_end_io(drbd_bio_t *bh, int uptodate)
{
	unsigned long flags=0;
	struct Tl_epoch_entry *e=NULL;
	struct Drbd_Conf* mdev;

	mdev=bh->b_private;
	PARANOIA_BUG_ON(!IS_VALID_MDEV(mdev));

	e = container_of(bh,struct Tl_epoch_entry,private_bio);
	PARANOIA_BUG_ON(!VALID_POINTER(e));
	D_ASSERT(e->block_id != ID_VACANT);

	spin_lock_irqsave(&mdev->ee_lock,flags);

	mark_buffer_uptodate(bh, uptodate);
	clear_bit(BH_Lock, &bh->b_state);
	smp_mb__after_clear_bit();

	list_del(&e->w.list);
	if(list_empty(&mdev->read_ee)) wake_up(&mdev->ee_wait);
	spin_unlock_irqrestore(&mdev->ee_lock,flags);

	drbd_chk_io_error(mdev,!uptodate);
	drbd_queue_work(mdev,&mdev->data.work,&e->w);
	dec_local(mdev);
}

/* writes on behalf of the partner, or resync writes,
 * "submitted" by the receiver.
 */
void drbd_dio_end_sec(struct buffer_head *bh, int uptodate)
{
	unsigned long flags=0;
	struct Tl_epoch_entry *e=NULL;
	struct Drbd_Conf* mdev;

	mdev=bh->b_private;
	PARANOIA_BUG_ON(!IS_VALID_MDEV(mdev));

	e = container_of(bh,struct Tl_epoch_entry,private_bio);
	PARANOIA_BUG_ON(!VALID_POINTER(e));
	D_ASSERT(e->block_id != ID_VACANT);

	spin_lock_irqsave(&mdev->ee_lock,flags);

	mark_buffer_uptodate(bh, uptodate);

	clear_bit(BH_Dirty, &bh->b_state);
	clear_bit(BH_Lock, &bh->b_state);
	smp_mb__after_clear_bit();

	list_del(&e->w.list);
	list_add_tail(&e->w.list,&mdev->done_ee);

	if (waitqueue_active(&mdev->ee_wait) &&
	    (list_empty(&mdev->active_ee) ||
	     list_empty(&mdev->sync_ee)))
		wake_up(&mdev->ee_wait);

	spin_unlock_irqrestore(&mdev->ee_lock,flags);

	drbd_chk_io_error(mdev,!uptodate);
	wake_asender(mdev);
	dec_local(mdev);
}

/* writes on Primary comming from drbd_make_request
 */
void drbd_dio_end(struct buffer_head *bh, int uptodate)
{
	struct Drbd_Conf* mdev;
	drbd_request_t *req;

	mdev = bh->b_private;
	PARANOIA_BUG_ON(!IS_VALID_MDEV(mdev));

	req = container_of(bh,struct drbd_request,private_bio);
	PARANOIA_BUG_ON(!VALID_POINTER(req));

	drbd_chk_io_error(mdev,!uptodate);
	drbd_end_req(req, RQ_DRBD_LOCAL, uptodate, drbd_req_get_sector(req));
	drbd_al_complete_io(mdev,drbd_req_get_sector(req));
	dec_local(mdev);
}

/* reads on Primary comming from drbd_make_request
 */
void drbd_read_bi_end_io(struct buffer_head *bh, int uptodate)
{
	struct Drbd_Conf* mdev;
	drbd_request_t *req;

	mdev = bh->b_private;
	PARANOIA_BUG_ON(!IS_VALID_MDEV(mdev));

	req = container_of(bh,struct drbd_request,private_bio);
	PARANOIA_BUG_ON(!VALID_POINTER(req));

	if (!uptodate) {
		// for the panic:
		drbd_chk_io_error(mdev,!uptodate); // handle panic and detach.
		if(mdev->on_io_error == PassOn) goto pass_on;
		// ok, if we survived this, retry:
		// FIXME sector ...
		if (DRBD_ratelimit(5*HZ,5))
			ERR("local read failed, retrying remotely\n");
		req->w.cb = w_read_retry_remote;
		drbd_queue_work(mdev,&mdev->data.work,&req->w);
	} else {
	pass_on:
		req->master_bio->b_end_io(req->master_bio,uptodate);
		dec_ap_bio(mdev);

		INVALIDATE_MAGIC(req);
		mempool_free(req,drbd_request_mempool);
	}
	dec_local(mdev);
}

#else

/* used for synchronous meta data and bitmap IO
 * submitted by drbd_md_sync_page_io()
 */
int drbd_md_io_complete(struct bio *bio, unsigned int bytes_done, int error)
{
	if (bio->bi_size)
		return 1;

	complete((struct completion*)bio->bi_private);
	return 0;
}

/* reads on behalf of the partner,
 * "submitted" by the receiver
 */
int enslaved_read_bi_end_io(struct bio *bio, unsigned int bytes_done, int error)
{
	unsigned long flags=0;
	struct Tl_epoch_entry *e=NULL;
	struct Drbd_Conf* mdev;

	mdev=bio->bi_private;
	PARANOIA_BUG_ON(!IS_VALID_MDEV(mdev));

	/* we should be called via bio_endio, so this should never be the case
	 * but "everyone else does it", and so do we ;)		-lge
	 */
	ERR_IF (bio->bi_size)
		return 1;

	e = container_of(bio,struct Tl_epoch_entry,private_bio);
	PARANOIA_BUG_ON(!VALID_POINTER(e));
	D_ASSERT(e->block_id != ID_VACANT);

	spin_lock_irqsave(&mdev->ee_lock,flags);
	list_del(&e->w.list);
	if(list_empty(&mdev->read_ee)) wake_up(&mdev->ee_wait);
	spin_unlock_irqrestore(&mdev->ee_lock,flags);

	drbd_chk_io_error(mdev,error);
	drbd_queue_work(mdev,&mdev->data.work,&e->w);
	dec_local(mdev);
	return 0;
}

/* writes on behalf of the partner, or resync writes,
 * "submitted" by the receiver.
 */
int drbd_dio_end_sec(struct bio *bio, unsigned int bytes_done, int error)
{
	unsigned long flags=0;
	struct Tl_epoch_entry *e=NULL;
	struct Drbd_Conf* mdev;

	mdev=bio->bi_private;
	PARANOIA_BUG_ON(!IS_VALID_MDEV(mdev));

	// see above
	ERR_IF (bio->bi_size)
		return 1;

	e = container_of(bio,struct Tl_epoch_entry,private_bio);
	PARANOIA_BUG_ON(!VALID_POINTER(e));
	D_ASSERT(e->block_id != ID_VACANT);

	spin_lock_irqsave(&mdev->ee_lock,flags);
	list_del(&e->w.list);
	list_add_tail(&e->w.list,&mdev->done_ee);

	if (waitqueue_active(&mdev->ee_wait) &&
	    (list_empty(&mdev->active_ee) ||
	     list_empty(&mdev->sync_ee)))
		wake_up(&mdev->ee_wait);

	spin_unlock_irqrestore(&mdev->ee_lock,flags);

	drbd_chk_io_error(mdev,error);
	wake_asender(mdev);
	dec_local(mdev);
	return 0;
}

/* writes on Primary comming from drbd_make_request
 */
int drbd_dio_end(struct bio *bio, unsigned int bytes_done, int error)
{
	struct Drbd_Conf* mdev=bio->bi_private;
	drbd_request_t *req;
	sector_t rsector;

	// see above
	ERR_IF (bio->bi_size)
		return 1;

	PARANOIA_BUG_ON(!IS_VALID_MDEV(mdev));

	req = container_of(bio,struct drbd_request,private_bio);
	PARANOIA_BUG_ON(!VALID_POINTER(req));

	drbd_chk_io_error(mdev,error);
	rsector = drbd_req_get_sector(req);
        // the bi_sector of the bio gets modified somewhere in drbd_end_req()!
	drbd_end_req(req, RQ_DRBD_LOCAL, (error == 0), rsector);
	drbd_al_complete_io(mdev,rsector);
	dec_local(mdev);
	return 0;
}

/* reads on Primary comming from drbd_make_request
 */
int drbd_read_bi_end_io(struct bio *bio, unsigned int bytes_done, int error)
{
	struct Drbd_Conf* mdev = bio->bi_private;
	drbd_request_t *req;

	// see above
	ERR_IF (bio->bi_size)
		return 1;

#if 0
	{
		static int ccc=1;

		if(ccc++ % 100 == 0) {
			ERR("Injecting IO error.\n");
			error=-5;
			clear_bit(BIO_UPTODATE,&bio->bi_flags);
		}
	}
#endif

	PARANOIA_BUG_ON(!IS_VALID_MDEV(mdev));

	req = container_of(bio,struct drbd_request,private_bio);
	PARANOIA_BUG_ON(!VALID_POINTER(req));

	if (error) {
		drbd_chk_io_error(mdev,error); // handle panic and detach.
		if(mdev->on_io_error == PassOn) goto pass_on;
		// ok, if we survived this, retry:
		// FIXME sector ...
		if (DRBD_ratelimit(5*HZ,5))
			ERR("local read failed, retrying remotely\n");
		req->w.cb = w_read_retry_remote;
		drbd_queue_work(mdev,&mdev->data.work,&req->w);
	} else {
	pass_on:
		bio_endio(req->master_bio,req->master_bio->bi_size,error);
		dec_ap_bio(mdev);

		INVALIDATE_MAGIC(req);
		mempool_free(req,drbd_request_mempool);
	}

	dec_local(mdev);
	return 0;
}
#endif

int w_io_error(drbd_dev* mdev, struct drbd_work* w,int cancel)
{
	drbd_request_t *req = (drbd_request_t*)w;
	int ok;

	// TODO send a "set_out_of_sync" packet to the peer

	INVALIDATE_MAGIC(req);
	mempool_free(req,drbd_request_mempool);

	if(unlikely(cancel)) return 1;

	ok = drbd_io_error(mdev);
	if(unlikely(!ok)) ERR("Sending in w_io_error() failed\n");
	return ok;
}

int w_read_retry_remote(drbd_dev* mdev, struct drbd_work* w,int cancel)
{
	drbd_request_t *req = (drbd_request_t*)w;
	int ok;

	smp_rmb();
	if ( cancel ||
	     mdev->cstate < Connected ||
	     test_bit(PARTNER_DISKLESS,&mdev->flags) ) {
		drbd_panic("WE ARE LOST. Local IO failure, no peer.\n");

		// does not make much sense, but anyways...
		drbd_bio_endio(req->master_bio,0);
		dec_ap_bio(mdev);
		mempool_free(req,drbd_request_mempool);
		return 1;
	}

	// FIXME: what if partner was SyncTarget, and is out of sync for
	// this area ?? ... should be handled in the receiver.
	inc_ap_pending(mdev);
	ok = drbd_read_remote(mdev,req);
	if(unlikely(!ok)) {
		ERR("drbd_read_remote() failed\n");
		/* dec_ap_pending and bio_io_error are done in
		 * drbd_fail_pending_reads
		 */
	}
	return ok;
}

int w_resync_inactive(drbd_dev *mdev, struct drbd_work *w, int cancel)
{
	ERR_IF(cancel) return 1;
	ERR("resync inactive, but callback triggered??\n");
	return 0;
}

/* FIXME
 * not used any longer, they now use e_end_resync_block.
 * maybe remove again?
 */
int w_is_resync_read(drbd_dev *mdev, struct drbd_work *w, int unused)
{
	ERR("%s: Typecheck only, should never be called!\n", __FUNCTION__ );
	return 0;
}

/* in case we need it. currently unused,
 * since should be assigned to "w_read_retry_remote"
 */
int w_is_app_read(drbd_dev *mdev, struct drbd_work *w, int unused)
{
	ERR("%s: Typecheck only, should never be called!\n", __FUNCTION__ );
	return 0;
}

void resync_timer_fn(unsigned long data)
{
	unsigned long flags;
	drbd_dev* mdev = (drbd_dev*) data;

	spin_lock_irqsave(&mdev->req_lock,flags);

	if(likely(!test_and_clear_bit(STOP_SYNC_TIMER,&mdev->flags))) {
		mdev->resync_work.cb = w_make_resync_request;
	} else {
		mdev->resync_work.cb = w_resume_next_sg;
	}

	if(list_empty(&mdev->resync_work.list)) {
		_drbd_queue_work(&mdev->data.work,&mdev->resync_work);
	} else INFO("Avoided requeue of resync_work\n");

	spin_unlock_irqrestore(&mdev->req_lock,flags);
}

int w_make_resync_request(drbd_dev* mdev, struct drbd_work* w,int cancel)
{
	sector_t sector;
	int number,i,size;

	PARANOIA_BUG_ON(w != &mdev->resync_work);

	if(unlikely(cancel)) return 1;
	if(unlikely(mdev->cstate < Connected)) {
		ERR("Confused in w_make_resync_request()! cstate < Connected");
		return 0;
	}

	D_ASSERT(mdev->cstate == SyncTarget);

#define SLEEP_TIME (HZ/10)

        number = SLEEP_TIME*mdev->sync_conf.rate / ((BM_BLOCK_SIZE/1024)*HZ);

        if(number > 1000) number=1000;  // Remove later
	if (atomic_read(&mdev->rs_pending_cnt)>1200) {
		// INFO("pending cnt high -- throttling resync.\n");
		goto requeue;
	}

	for(i=0;i<number;i++) {

	next_sector:
		size = BM_BLOCK_SIZE;
		sector = bm_get_sector(mdev->mbds_id,&size);

		if (sector == MBDS_DONE) {
			mdev->resync_work.cb = w_resync_inactive;
			return 1;
		}

		if(!drbd_rs_begin_io(mdev,sector)) return 0;

		if(unlikely(!bm_get_bit(mdev->mbds_id,sector,BM_BLOCK_SIZE))) {
		      //INFO("Block got synced while in drbd_rs_begin_io()\n");
			drbd_rs_complete_io(mdev,sector);
			goto next_sector;
		}

		inc_rs_pending(mdev);
		if(!drbd_send_drequest(mdev,RSDataRequest,
				       sector,size,ID_SYNCER)) {
			ERR("drbd_send_drequest() failed, aborting...");
			dec_rs_pending(mdev,HERE);
			return 0; // FAILED. worker will abort!
		}
	}

 requeue:
	if(bm_is_rs_done(mdev->mbds_id)) {
		mdev->resync_work.cb = w_resync_inactive;
		return 1;
	}

	mdev->resync_timer.expires = jiffies + SLEEP_TIME;
	add_timer(&mdev->resync_timer);
	return 1;
}

int drbd_resync_finished(drbd_dev* mdev)
{
	unsigned long dt;
	sector_t n;

	D_ASSERT(mdev->rs_left == 0);

	dt = (jiffies - mdev->rs_start) / HZ + 1;
	n = mdev->rs_total>>1;
	sector_div(n,dt);
	INFO("Resync done (total %lu sec; %lu K/sec)\n",
	     dt,(unsigned long)n);

	if (mdev->cstate == SyncTarget) {
		mdev->gen_cnt[Flags] |= MDF_Consistent;
		drbd_md_write(mdev);
	}
	mdev->rs_total = 0;

	// assert that all bit-map parts are cleared.
	D_ASSERT(list_empty(&mdev->resync->lru));

	set_cstate(mdev,Connected); // w_resume_next_sg() gets called here.
	return 1;
}

int w_e_end_data_req(drbd_dev *mdev, struct drbd_work *w, int cancel)
{
	struct Tl_epoch_entry *e = (struct Tl_epoch_entry*)w;
	int ok;

	if(unlikely(cancel)) {
		spin_lock_irq(&mdev->ee_lock);
		drbd_put_ee(mdev,e);
		spin_unlock_irq(&mdev->ee_lock);
		dec_unacked(mdev,HERE);
		return 1;
	}

	if(likely(drbd_bio_uptodate(&e->private_bio))) {
		ok=drbd_send_block(mdev, DataReply, e);
	} else {
		ok=drbd_send_ack(mdev,NegDReply,e);
		if (DRBD_ratelimit(5*HZ,5))
			ERR("Sending NegDReply. I guess it gets messy.\n");
		drbd_io_error(mdev);
	}

	dec_unacked(mdev,HERE);

	spin_lock_irq(&mdev->ee_lock);
	drbd_put_ee(mdev,e);
	spin_unlock_irq(&mdev->ee_lock);

	if(unlikely(!ok)) ERR("drbd_send_block() failed\n");
	return ok;
}

int w_e_end_rsdata_req(drbd_dev *mdev, struct drbd_work *w, int cancel)
{
	struct Tl_epoch_entry *e = (struct Tl_epoch_entry*)w;
	int ok;

	if(unlikely(cancel)) {
		spin_lock_irq(&mdev->ee_lock);
		drbd_put_ee(mdev,e);
		spin_unlock_irq(&mdev->ee_lock);
		dec_unacked(mdev,HERE);
		return 1;
	}

	drbd_rs_complete_io(mdev,drbd_ee_get_sector(e));

	if(likely(drbd_bio_uptodate(&e->private_bio))) {
		if (likely( !test_bit(PARTNER_DISKLESS,&mdev->flags) )) {
			inc_rs_pending(mdev);
			ok=drbd_send_block(mdev, RSDataReply, e);
		} else {
			if (DRBD_ratelimit(5*HZ,5))
				ERR("Not sending RSDataReply, partner DISKLESS!\n");
			ok=1;
		}
	} else {
		ok=drbd_send_ack(mdev,NegRSDReply,e);
		if (DRBD_ratelimit(5*HZ,5))
			ERR("Sending NegDReply. I guess it gets messy.\n");
		drbd_io_error(mdev);
	}

	dec_unacked(mdev,HERE);

	spin_lock_irq(&mdev->ee_lock);
	drbd_put_ee(mdev,e);
	spin_unlock_irq(&mdev->ee_lock);

	if(unlikely(!ok)) ERR("drbd_send_block() failed\n");
	return ok;
}

int w_try_send_barrier(drbd_dev *mdev, struct drbd_work *w, int cancel)
{
	int ok=1;

	if(unlikely(cancel)) return ok;

	down(&mdev->data.mutex);
	if(test_and_clear_bit(ISSUE_BARRIER,&mdev->flags)) {
		ok = _drbd_send_barrier(mdev);
	}
	up(&mdev->data.mutex);

	return ok;
}

int w_send_write_hint(drbd_dev *mdev, struct drbd_work *w, int cancel)
{
	if (cancel) return 1;
	NOT_IN_26(clear_bit(UNPLUG_QUEUED,&mdev->flags));
	return drbd_send_short_cmd(mdev,WriteHint);
}

STATIC void drbd_global_lock(void)
{
	int i;

	local_irq_disable();
	for (i=0; i < minor_count; i++) {
		spin_lock(&drbd_conf[i].req_lock);
	}
}

STATIC void drbd_global_unlock(void)
{
	int i;

	for (i=0; i < minor_count; i++) {
		spin_unlock(&drbd_conf[i].req_lock);
	}
	local_irq_enable();
}

STATIC void _drbd_rs_resume(drbd_dev *mdev)
{
	Drbd_CState ns;

	ns = mdev->cstate - (PausedSyncS - SyncSource);
	D_ASSERT(ns == SyncSource || ns == SyncTarget);

	INFO("Syncer continues.\n");
	_set_cstate(mdev,ns);

	if(mdev->cstate == SyncTarget) {
		ERR_IF(test_bit(STOP_SYNC_TIMER,&mdev->flags)) {
			clear_bit(STOP_SYNC_TIMER,&mdev->flags);
		}
		D_ASSERT(mdev->rs_left > 0);
		mod_timer(&mdev->resync_timer,jiffies);
	}
}


STATIC void _drbd_rs_pause(drbd_dev *mdev)
{
	Drbd_CState ns;

	D_ASSERT(mdev->cstate == SyncSource || mdev->cstate == SyncTarget);
	ns = mdev->cstate + (PausedSyncS - SyncSource);

	if(mdev->cstate == SyncTarget) set_bit(STOP_SYNC_TIMER,&mdev->flags);

	_set_cstate(mdev,ns);
	INFO("Syncer waits for sync group.\n");
}

STATIC int _drbd_pause_higher_sg(drbd_dev *mdev)
{
	drbd_dev *odev;
	int i,rv=0;

	for (i=0; i < minor_count; i++) {
		odev = drbd_conf + i;
		if ( odev->sync_conf.group > mdev->sync_conf.group
		     && ( odev->cstate == SyncSource || 
			  odev->cstate == SyncTarget ) ) {
			_drbd_rs_pause(odev);
			rv = 1;
		}
	}

	return rv;
}

STATIC int _drbd_lower_sg_running(drbd_dev *mdev)
{
	drbd_dev *odev;
	int i,rv=0;

	for (i=0; i < minor_count; i++) {
		odev = drbd_conf + i;
		if ( odev->sync_conf.group < mdev->sync_conf.group
		     && ( odev->cstate == SyncSource || 
			  odev->cstate == SyncTarget ) ) {
			rv = 1;
		}
	}

	return rv;
}

STATIC int _drbd_resume_lower_sg(drbd_dev *mdev)
{
	drbd_dev *odev;
	int i,rv=0;

	for (i=0; i < minor_count; i++) {
		odev = drbd_conf + i;
		if ( odev->sync_conf.group < mdev->sync_conf.group
		     && ( odev->cstate == PausedSyncS || 
			  odev->cstate == PausedSyncT ) ) {
			_drbd_rs_resume(odev);
			rv = 1;
		}
	}

	return rv;
}

int w_resume_next_sg(drbd_dev* mdev, struct drbd_work* w, int unused)
{
	drbd_dev *odev;
	int i,ng=10000;

	PARANOIA_BUG_ON(w != &mdev->resync_work);

	drbd_global_lock();

	for (i=0; i < minor_count; i++) {
		odev = drbd_conf + i;
		if ( odev->sync_conf.group == mdev->sync_conf.group
		     && ( odev->cstate == SyncSource || 
			  odev->cstate == SyncTarget ) ) {
			goto out; // Sync on an other device in this group
			          // still runs.
		}
	}

	for (i=0; i < minor_count; i++) { // find next sync group
		odev = drbd_conf + i;
		if ( odev->sync_conf.group > mdev->sync_conf.group
		     && odev->sync_conf.group < ng && 
		     (odev->cstate==PausedSyncS || odev->cstate==PausedSyncT)){
		  ng = odev->sync_conf.group;
		}
	}

	for (i=0; i < minor_count; i++) { // resume all devices in next group
		odev = drbd_conf + i;
		if ( odev->sync_conf.group == ng &&
		     (odev->cstate==PausedSyncS || odev->cstate==PausedSyncT)){
			_drbd_rs_resume(odev);
		}
	}

 out:
	drbd_global_unlock();
	w->cb = w_resync_inactive;

	return 1;
}

void drbd_alter_sg(drbd_dev *mdev, int ng)
{
	int c = 0, p = 0;
	int d = (ng - mdev->sync_conf.group);

	drbd_global_lock();
	mdev->sync_conf.group = ng;

	if( ( mdev->cstate == PausedSyncS || 
	      mdev->cstate == PausedSyncT ) && ( d < 0 ) ) {
		if(_drbd_pause_higher_sg(mdev)) c=1;
		else if(!_drbd_lower_sg_running(mdev)) c=1;
		if(c) _drbd_rs_resume(mdev);
	}

	if( ( mdev->cstate == SyncSource || 
	      mdev->cstate == SyncTarget ) && ( d > 0 ) ) {
		if(_drbd_resume_lower_sg(mdev)) p=1;
		else if(_drbd_lower_sg_running(mdev)) p=1;
		if(p) _drbd_rs_pause(mdev);
	}
	drbd_global_unlock();
}

void drbd_start_resync(drbd_dev *mdev, Drbd_CState side)
{
	set_cstate(mdev,side);
	mdev->rs_left=mdev->rs_total;
	mdev->rs_start=jiffies;
	mdev->rs_mark_left=mdev->rs_left;
	mdev->rs_mark_time=mdev->rs_start;

	INFO("Resync started as %s (need to sync %lu KB).\n",
	     side == SyncTarget ? "target" : "source", 
	     (unsigned long) (mdev->rs_left+1)>>1);

	// FIXME: this was a PARANOIA_BUG_ON, but it triggered! ??
	ERR_IF(mdev->resync_work.cb != w_resync_inactive)
		return;

	if ( mdev->rs_left == 0 ) {
		drbd_resync_finished(mdev);
		return;
	}

	if(mdev->cstate == SyncTarget) {
		mdev->gen_cnt[Flags] &= ~MDF_Consistent;
		bm_reset(mdev->mbds_id);
		D_ASSERT(!test_bit(STOP_SYNC_TIMER,&mdev->flags));
		mod_timer(&mdev->resync_timer,jiffies);
	} else {
		// If we are SyncSource we must be consistent :)
		mdev->gen_cnt[Flags] |= MDF_Consistent;
	}

	drbd_md_write(mdev);

	drbd_global_lock();
	if (mdev->cstate == SyncTarget || mdev->cstate == SyncSource) {
		_drbd_pause_higher_sg(mdev);
		if(_drbd_lower_sg_running(mdev)) {
			_drbd_rs_pause(mdev);
		}
	} /* else:
	   * thread of other mdev already paused us,
	   * or something very strange happend to our cstate!
	   * I really hate it that we can't have a consistent view of cstate.
	   * maybe we even need yet an other smp_mb() ?
	   */
	drbd_global_unlock();
}

int drbd_worker(struct Drbd_thread *thi)
{
	drbd_dev *mdev = thi->mdev;
	struct drbd_work *w = 0;
	LIST_HEAD(work_list);
	int intr,i;

	sprintf(current->comm, "drbd%d_worker", (int)(mdev-drbd_conf));

	mdev->resync_timer.function = resync_timer_fn;
	mdev->resync_timer.data = (unsigned long) mdev;

	for (;;) {
		intr = down_interruptible(&mdev->data.work.s);

		if (unlikely(drbd_did_panic == DRBD_MAGIC)) {
			set_current_state(TASK_ZOMBIE);
			schedule(); // commit suicide
		}

		if (intr) {
			D_ASSERT(intr == -EINTR);
			drbd_flush_signals(current);
			ERR_IF (get_t_state(thi) == Running)
				continue;
			break;
		}

		if (get_t_state(thi) != Running) break;
		/* With this break, we have done an down() but not consumed
		   the entry from the list. The cleanup code takes care of
		   this...   */

		w = 0;
		spin_lock_irq(&mdev->req_lock);
		D_ASSERT(!list_empty(&mdev->data.work.q));
		w = list_entry(mdev->data.work.q.next,struct drbd_work,list);
		list_del_init(&w->list);
		spin_unlock_irq(&mdev->req_lock);

		if(!w->cb(mdev,w, mdev->cstate < Connected )) {
			//WARN("worker: a callback failed! \n");
			if (mdev->cstate >= Connected)
				set_cstate(mdev,NetworkFailure);
			drbd_thread_restart_nowait(&mdev->receiver);
		}
	}

	drbd_wait_ee(mdev,&mdev->read_ee);

	i = 0;
	spin_lock_irq(&mdev->req_lock);
  again:
	list_splice_init(&mdev->data.work.q,&work_list);
	spin_unlock_irq(&mdev->req_lock);

	while(!list_empty(&work_list)) {
		w = list_entry(work_list.next, struct drbd_work,list);
		list_del_init(&w->list);
		w->cb(mdev,w,1);
		i++;
	}

	spin_lock_irq(&mdev->req_lock);
	ERR_IF(!list_empty(&mdev->data.work.q))
		goto again;
	sema_init(&mdev->data.work.s,0);
	spin_unlock_irq(&mdev->req_lock);

	INFO("worker terminated\n");

	return 0;
}
