/*
-*- linux-c -*-
   drbd_worker.c
   Kernel module for 2.4.x/2.6.x Kernels

   This file is part of drbd by Philipp Reisner.

   Copyright (C) 2003-2004, Philipp Reisner <philipp.reisner@linbit.com>.
   Copyright (C) 2003-2004, Lars Ellenberg <l.g.e@web.de>.
	authors.

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
#include <linux/version.h>

#include <linux/sched.h>
#include <linux/smp_lock.h>
#include <linux/wait.h>
#include <linux/mm.h>
#include <linux/drbd_config.h>
#include <linux/mm_inline.h> // for the page_count macro on RH/Fedora
#include <linux/slab.h>
#include <linux/random.h>

#include <linux/drbd.h>
#include "drbd_int.h"

/* I choose to have all block layer end_io handlers defined here.

 * For all these callbacks, note the follwing:
 * The callbacks will be called in irq context by the IDE drivers,
 * and in Softirqs/Tasklets/BH context by the SCSI drivers.
 * Try to get the locking right :)
 *
 */

/* used for synchronous meta data and bitmap IO
 * submitted by drbd_md_sync_page_io()
 */
int drbd_md_io_complete(struct bio *bio, unsigned int bytes_done, int error)
{
	if (bio->bi_size) return 1;

	complete((struct completion*)bio->bi_private);
	return 0;
}

/* reads on behalf of the partner,
 * "submitted" by the receiver
 */
int drbd_endio_read_sec(struct bio *bio, unsigned int bytes_done, int error)
{
	unsigned long flags=0;
	struct Tl_epoch_entry *e=NULL;
	struct Drbd_Conf* mdev;

	e = bio->bi_private;
	mdev = e->mdev;

	/* We are called each time a part of the bio is finished, but
	 * we are only interested when the whole bio is finished, therefore
	 * return as long as bio->bio_size is positive.
	 */
	if (bio->bi_size) return 1;

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
int drbd_endio_write_sec(struct bio *bio, unsigned int bytes_done, int error)
{
	unsigned long flags=0;
	struct Tl_epoch_entry *e=NULL;
	struct Drbd_Conf* mdev;
	int do_wake;

	e = bio->bi_private;
	mdev = e->mdev;

	// see above
	if (bio->bi_size) return 1;

	PARANOIA_BUG_ON(!VALID_POINTER(e));
	D_ASSERT(e->block_id != ID_VACANT);

	spin_lock_irqsave(&mdev->ee_lock,flags);
	mdev->epoch_size++;
	list_del(&e->w.list);
	list_add_tail(&e->w.list,&mdev->done_ee);

	do_wake = is_syncer_block_id(e->block_id)
		? list_empty(&mdev->sync_ee)
		: list_empty(&mdev->active_ee);

	spin_unlock_irqrestore(&mdev->ee_lock,flags);

	if (do_wake) wake_up(&mdev->ee_wait);

	if( !hlist_unhashed(&e->colision) ) {
		spin_lock_irqsave(&mdev->tl_lock,flags);
		hlist_del_init(&e->colision);
		spin_unlock_irqrestore(&mdev->tl_lock,flags);
	}

	drbd_chk_io_error(mdev,error);
	wake_asender(mdev);
	dec_local(mdev);
	return 0;
}

/* writes on Primary comming from drbd_make_request
 */
int drbd_endio_write_pri(struct bio *bio, unsigned int bytes_done, int error)
{
	drbd_request_t *req=bio->bi_private;
	struct Drbd_Conf* mdev=req->mdev;
	sector_t rsector;

	// see above
	if (bio->bi_size) return 1;

	drbd_chk_io_error(mdev,error);
	rsector = drbd_req_get_sector(req);
        // the bi_sector of the bio gets modified somewhere in drbd_end_req()!
	drbd_end_req(req, RQ_DRBD_LOCAL, (error == 0), rsector);
	drbd_al_complete_io(mdev,rsector);
	dec_local(mdev);
	bio_put(bio);
	return 0;
}

/* reads on Primary comming from drbd_make_request
 */
int drbd_endio_read_pri(struct bio *bio, unsigned int bytes_done, int error)
{
	drbd_request_t *req=bio->bi_private;
	struct Drbd_Conf* mdev=req->mdev;

	if (bio->bi_size) return 1;

	/* READAs may fail.
	 * upper layers need to be able to handle that themselves */
	if (bio_rw(bio) == READA) goto pass_on;
	if (error) {
		drbd_chk_io_error(mdev,error); // handle panic and detach.
		if(mdev->bc->on_io_error == PassOn) goto pass_on;
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

		drbd_req_free(req);
	}

	bio_put(bio);
	dec_local(mdev);
	return 0;
}

int w_io_error(drbd_dev* mdev, struct drbd_work* w,int cancel)
{
	drbd_request_t *req = (drbd_request_t*)w;
	int ok;

	/* FIXME send a "set_out_of_sync" packet to the peer
	 * in the PassOn case...
	 * in the Detach (or Panic) case, we (try to) send
	 * a "we are diskless" param packet anyways, and the peer
	 * will then set the FullSync bit in the meta data ...
	 */
	D_ASSERT(mdev->bc->on_io_error != PassOn);

	drbd_req_free(req);

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
	     mdev->state.conn < Connected ||
	     mdev->state.pdsk <= Inconsistent ) {
		drbd_panic("WE ARE LOST. Local IO failure, no peer.\n");

		// does not make much sense, but anyways...
		drbd_bio_endio(req->master_bio,0);
		dec_ap_bio(mdev);
		drbd_req_free(req);
		return 1;
	}

	// FIXME: what if partner was SyncTarget, and is out of sync for
	// this area ?? ... should be handled in the receiver.

	ok = drbd_io_error(mdev);
	if(unlikely(!ok)) ERR("Sending in w_read_retry_remote() failed\n");
	
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

#define SLEEP_TIME (HZ/10)

int w_make_resync_request(drbd_dev* mdev, struct drbd_work* w,int cancel)
{
	unsigned long bit;
	sector_t sector;
	const sector_t capacity = drbd_get_capacity(mdev->this_bdev);
	int number,i,size;

	PARANOIA_BUG_ON(w != &mdev->resync_work);

	if(unlikely(cancel)) return 1;

	if(unlikely(mdev->state.conn < Connected)) {
		ERR("Confused in w_make_resync_request()! cstate < Connected");
		return 0;
	}

	if (mdev->state.conn != SyncTarget) {
		ERR("%s in w_make_resync_request\n", conns_to_name(mdev->state.conn));
	}

        number = SLEEP_TIME*mdev->sync_conf.rate / ((BM_BLOCK_SIZE/1024)*HZ);

	if (atomic_read(&mdev->rs_pending_cnt)>number) {
		goto requeue;
	}
	number -= atomic_read(&mdev->rs_pending_cnt);

	for(i=0;i<number;i++) {

	next_sector:
		size = BM_BLOCK_SIZE;
		bit  = drbd_bm_find_next(mdev);

		if (bit == -1UL) {
			/* FIXME either test_and_set some bit,
			 * or make this the _only_ place that is allowed
			 * to assign w_resync_inactive! */
			mdev->resync_work.cb = w_resync_inactive;
			return 1;
		}

		sector = BM_BIT_TO_SECT(bit);

		if(!drbd_rs_begin_io(mdev,sector)) {
			// we have been interrupted, probably connection lost!
			D_ASSERT(signal_pending(current));
			return 0;
		}

		if(unlikely( drbd_bm_test_bit(mdev,bit) == 0 )) {
		      //INFO("Block got synced while in drbd_rs_begin_io()\n");
			drbd_rs_complete_io(mdev,sector);
			goto next_sector;
		}

#if DRBD_MAX_SEGMENT_SIZE > BM_BLOCK_SIZE
		// try to find some adjacent bits...
		while ( drbd_bm_test_bit(mdev,bit+1) ) {
			// stop if we have the already the maximum req size
			if(size == DRBD_MAX_SEGMENT_SIZE) break;
			// do not leafe the current BM_EXTEND
			if(( (bit+1) & BM_BLOCKS_PER_BM_EXT_MASK ) == 0) break;
			bit++;
			size += BM_BLOCK_SIZE;
			i++;
		}
		drbd_bm_set_find(mdev,bit+1);
#endif

		if (sector + (size>>9) > capacity) size = (capacity-sector)<<9;
		inc_rs_pending(mdev);
		if(!drbd_send_drequest(mdev,RSDataRequest,
				       sector,size,ID_SYNCER)) {
			ERR("drbd_send_drequest() failed, aborting...");
			dec_rs_pending(mdev);
			return 0; // FAILED. worker will abort!
		}
	}

	if(drbd_bm_rs_done(mdev)) {
		/* last syncer _request_ was sent,
		 * but the RSDataReply not yet received.  sync will end (and
		 * next sync group will resume), as soon as we receive the last
		 * resync data block, and the last bit is cleared.
		 * until then resync "work" is "inactive" ...
		 */
		mdev->resync_work.cb = w_resync_inactive;
		return 1;
	}

 requeue:
	mod_timer(&mdev->resync_timer, jiffies + SLEEP_TIME);
	return 1;
}

int drbd_resync_finished(drbd_dev* mdev)
{
	unsigned long db,dt,dbdt;

	dt = (jiffies - mdev->rs_start - mdev->rs_paused) / HZ;
	if (dt <= 0) dt=1;
	db = mdev->rs_total;
	dbdt = Bit2KB(db/dt);
	mdev->rs_paused /= HZ;
	INFO("Resync done (total %lu sec; paused %lu sec; %lu K/sec)\n",
	     dt + mdev->rs_paused, mdev->rs_paused, dbdt);

	// assert that all bit-map parts are cleared.
	D_ASSERT(list_empty(&mdev->resync->lru));
	D_ASSERT(drbd_bm_total_weight(mdev) == 0);
	mdev->rs_total  = 0;
	mdev->rs_paused = 0;

	if ( mdev->state.conn == SyncTarget ) {
		if( mdev->p_uuid ) {
			int i;
			for ( i=Bitmap ; i<=History_end ; i++ ) {
				_drbd_uuid_set(mdev,i,mdev->p_uuid[i]);
			}
			drbd_uuid_set_bm(mdev,0UL); //Rotate peer's bitmap-UUID
			drbd_uuid_set(mdev,Current,mdev->p_uuid[Current]);
		} else {
			ERR("mdev->p_uuid is NULL! BUG\n");
		}
	}

	drbd_uuid_set_bm(mdev,0UL);

	if ( mdev->p_uuid ) {
		kfree(mdev->p_uuid);
		mdev->p_uuid = NULL;
	}

	drbd_request_state(mdev,NS3(conn,Connected,
				    disk,UpToDate,
				    pdsk,UpToDate));

	drbd_md_write(mdev);

	return 1;
}

int w_e_end_data_req(drbd_dev *mdev, struct drbd_work *w, int cancel)
{
	struct Tl_epoch_entry *e = (struct Tl_epoch_entry*)w;
	int ok;

	if(unlikely(cancel)) {
		drbd_free_ee(mdev,e);
		dec_unacked(mdev);
		return 1;
	}

	if(likely(drbd_bio_uptodate(e->private_bio))) {
		ok=drbd_send_block(mdev, DataReply, e);
	} else {
		ok=drbd_send_ack(mdev,NegDReply,e);
		if (DRBD_ratelimit(5*HZ,5))
			ERR("Sending NegDReply. I guess it gets messy.\n");
		drbd_io_error(mdev);
	}

	dec_unacked(mdev);

	spin_lock_irq(&mdev->ee_lock);
	if( drbd_bio_has_active_page(e->private_bio) ) {
		/* This might happen if sendpage() has not finished */
		list_add_tail(&e->w.list,&mdev->net_ee);
	} else {
		drbd_free_ee(mdev,e);
	}
	spin_unlock_irq(&mdev->ee_lock);

	if(unlikely(!ok)) ERR("drbd_send_block() failed\n");
	return ok;
}

int w_e_end_rsdata_req(drbd_dev *mdev, struct drbd_work *w, int cancel)
{
	struct Tl_epoch_entry *e = (struct Tl_epoch_entry*)w;
	int ok;

	if(unlikely(cancel)) {
		drbd_free_ee(mdev,e);
		dec_unacked(mdev);
		return 1;
	}

	drbd_rs_complete_io(mdev,drbd_ee_get_sector(e));

	if(likely(drbd_bio_uptodate(e->private_bio))) {
		if (likely( mdev->state.pdsk >= Inconsistent )) {
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

	dec_unacked(mdev);

	spin_lock_irq(&mdev->ee_lock);
	if( drbd_bio_has_active_page(e->private_bio) ) {
		/* This might happen if sendpage() has not finished */
		list_add_tail(&e->w.list,&mdev->net_ee);
	} else {
		drbd_free_ee(mdev,e);
	}
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
	return drbd_send_short_cmd(mdev,UnplugRemote);
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

/** 
 * _drbd_rs_resume:
 * @reason: Name of the flag
 * Clears one of the three reason flags that could cause the suspension
 * of the resynchronisation process. In case all three are cleared it 
 * actually changes the state to SyncSource or SyncTarget.
 * Returns 1 iff the flag got cleared; 0 iff the flag was already cleared.
 */ 
STATIC int _drbd_rs_resume(drbd_dev *mdev, enum RSPauseReason reason)
{
	drbd_state_t os,ns;
	int r,doing=0;

	ns = os = mdev->state;

	switch(reason) {
	case AfterDependency:	ns.aftr_isp = 0;	break;
	case PeerImposed:	ns.peer_isp = 0;	break;
	case UserImposed:	ns.user_isp = 0;	break;
	}
	if(ns.aftr_isp == 0 && ns.peer_isp == 0 && ns.user_isp == 0) {
		if(os.conn == PausedSyncS) ns.conn=SyncSource, doing=1;
		if(os.conn == PausedSyncT) ns.conn=SyncTarget, doing=1;
	}

	// Call _drbd_set_state() in any way to set the _isp bits.
	r = _drbd_set_state(mdev,ns,ChgStateHard|ScheduleAfter);

	if(doing) {
		INFO("Syncer continues.\n");
		mdev->rs_paused += (long)jiffies-(long)mdev->rs_mark_time;

		if(ns.conn == SyncTarget) {
			D_ASSERT(!test_bit(STOP_SYNC_TIMER,&mdev->flags));
			mod_timer(&mdev->resync_timer,jiffies);
		}
	}
	return r != 2;
}

/** 
 * _drbd_rs_pause:
 * @reason: Name of the flag
 * Sets one of the three reason flags that could cause the suspension
 * of the resynchronisation process. In case the state was not alreay
 * PausedSyncT or PausedSyncS it changes the state into one of these.
 * Returns 1 iff the flag got set; 0 iff the flag was already set.
 */ 
STATIC int _drbd_rs_pause(drbd_dev *mdev, enum RSPauseReason reason)
{
	drbd_state_t os,ns;
	int r,doing=0;

	static const char *reason_txt[] = {
		[AfterDependency] = "dependency",
		[PeerImposed]     = "peer",
		[UserImposed]     = "user",
	};

	ns = os = mdev->state;

	if(os.conn == SyncSource) ns.conn=PausedSyncS, doing=1;
	if(os.conn == SyncTarget) ns.conn=PausedSyncT, doing=1;
	switch(reason) {
	case AfterDependency:	ns.aftr_isp = 1;	break;
	case PeerImposed:	ns.peer_isp = 1;	break;
	case UserImposed:	ns.user_isp = 1;	break;
	}

	// Call _drbd_set_state() in any way to set the _isp bits.
	r = _drbd_set_state(mdev,ns,ChgStateHard|ScheduleAfter);

	if(doing) {
		if( ns.conn == PausedSyncT ) 
			set_bit(STOP_SYNC_TIMER,&mdev->flags);

		mdev->rs_mark_time = jiffies;
		INFO("Resync suspended by %s.\n",reason_txt[reason]);
	}

	return r != 2;
}

STATIC int _drbd_may_sync_now(drbd_dev *mdev)
{
	drbd_dev *odev = mdev;

	while(1) {
		if( odev->sync_conf.after == -1 ) return 1;
		odev = drbd_conf + odev->sync_conf.after;
		if( odev->state.conn >= SyncSource &&
		    odev->state.conn <= PausedSyncT ) return 0;
	}
}

/** 
 * _drbd_pause_after:
 * Finds all devices that may not resync now, and causes them to
 * pause their resynchronisation.
 * Called from process context only ( ioctl and receiver ).
 */ 
STATIC int _drbd_pause_after(drbd_dev *mdev)
{
	drbd_dev *odev;
	int i, rv = 0;

	for (i=0; i < minor_count; i++) {
		odev = drbd_conf + i;
		if ( odev->state.conn == SyncSource ||
		     odev->state.conn == SyncTarget ) {
			if (! _drbd_may_sync_now(odev)) {
				_drbd_rs_pause(odev,AfterDependency);
				rv = 1;
			}
		}
	}

	return rv;
}

/** 
 * _drbd_resume_next:
 * Finds all devices that can resume resynchronisation
 * process, and causes them to resume.
 * Called from process context only ( ioctl and worker ).
 */ 
STATIC int _drbd_resume_next(drbd_dev *mdev)
{
	drbd_dev *odev;
	int i, rv = 0;

	for (i=0; i < minor_count; i++) {
		odev = drbd_conf + i;
		if ( odev->state.conn == PausedSyncS ||
		     odev->state.conn == PausedSyncT ) {
			if (_drbd_may_sync_now(odev)) {
				_drbd_rs_resume(odev,AfterDependency);
				rv = 1;
			}
		}
	}
	return rv;
}

int w_resume_next_sg(drbd_dev* mdev, struct drbd_work* w, int unused)
{
	PARANOIA_BUG_ON(w != &mdev->resync_work);

	drbd_global_lock();
	_drbd_resume_next(mdev);
	drbd_global_unlock();

	w->cb = w_resync_inactive;

	return 1;
}

void drbd_alter_sa(drbd_dev *mdev, int na)
{
	int changes;

	drbd_global_lock();
	mdev->sync_conf.after = na;

	do {
		changes  = _drbd_pause_after(mdev);
		changes |= _drbd_resume_next(mdev);
	} while (changes);

	drbd_global_unlock();
}

int drbd_resync_pause(drbd_dev *mdev, enum RSPauseReason reason)
{
	int rv;
	drbd_global_lock();
	rv = _drbd_rs_pause(mdev,reason);
	drbd_global_unlock();
	return rv;
}

int drbd_resync_resume(drbd_dev *mdev, enum RSPauseReason reason)
{
	int rv;
	drbd_global_lock();
	rv = _drbd_rs_resume(mdev,reason);
	drbd_global_unlock();
	return rv;
}


/**
 * drbd_start_resync:
 * @side: Either SyncSource or SyncTarget
 * Start the resync process. Called from process context only,
 * either ioctl or drbd_receiver.
 * Note, this function might bring your directly into one of the
 * PausedSync* states.
 */
void drbd_start_resync(drbd_dev *mdev, drbd_conns_t side)
{
	drbd_state_t os,ns;
	int r=0,p=0;

	if(side == SyncTarget) {
		drbd_bm_reset_find(mdev);
	} else /* side == SyncSource */ {
		u64 uuid;

		get_random_bytes(&uuid, sizeof(u64));
		drbd_uuid_set(mdev, Bitmap, uuid);
		drbd_send_sync_uuid(mdev,uuid);
		
		D_ASSERT(mdev->state.disk == UpToDate);
	}

	drbd_global_lock();
	ns = os = mdev->state;

	if(!_drbd_may_sync_now(mdev)) {
		ns.aftr_isp = 1;
		p = (PausedSyncS - SyncSource);
	}
	if( ns.peer_isp || ns.user_isp ) p = (PausedSyncS - SyncSource);

	ns.conn = side + p;

	if(side == SyncTarget) {
		ns.disk = Inconsistent;
	} else /* side == SyncSource */ {
		ns.pdsk = Inconsistent;
	}

	r = _drbd_set_state(mdev,ns,ChgStateVerbose);

	if ( r==1 ) {
		mdev->rs_total     =
		mdev->rs_mark_left = drbd_bm_total_weight(mdev);
		mdev->rs_paused    = 0;
		mdev->rs_start     =
		mdev->rs_mark_time = jiffies;
		_drbd_pause_after(mdev);
	}
	drbd_global_unlock();

	if ( r==1 ) {
		after_state_ch(mdev,os,ns);

		INFO("Began resync as %s (will sync %lu KB [%lu bits set]).\n",
		     conns_to_name(ns.conn),
		     (unsigned long) mdev->rs_total << (BM_BLOCK_SIZE_B-10),
		     (unsigned long) mdev->rs_total);

		if ( mdev->rs_total == 0 ) {
			drbd_resync_finished(mdev);
			return;
		}

		drbd_md_write(mdev);

		if( ns.conn == SyncTarget ) {
			D_ASSERT(!test_bit(STOP_SYNC_TIMER,&mdev->flags));
			mod_timer(&mdev->resync_timer,jiffies);
		}
	}
}

int drbd_worker(struct Drbd_thread *thi)
{
	drbd_dev *mdev = thi->mdev;
	struct drbd_work *w = 0;
	LIST_HEAD(work_list);
	int intr,i;

	sprintf(current->comm, "drbd%d_worker", (int)(mdev-drbd_conf));

	for (;;) {
		intr = down_interruptible(&mdev->data.work.s);

		if (unlikely(drbd_did_panic == DRBD_MAGIC)) {
			drbd_suicide();
		}

		if (intr) {
			D_ASSERT(intr == -EINTR);
			flush_signals(current);
			ERR_IF (get_t_state(thi) == Running)
				continue;
			break;
		}

		if (get_t_state(thi) != Running) break;
		/* With this break, we have done a down() but not consumed
		   the entry from the list. The cleanup code takes care of
		   this...   */

		w = 0;
		spin_lock_irq(&mdev->req_lock);
		D_ASSERT(!list_empty(&mdev->data.work.q));
		w = list_entry(mdev->data.work.q.next,struct drbd_work,list);
		list_del_init(&w->list);
		spin_unlock_irq(&mdev->req_lock);

		if(!w->cb(mdev,w, mdev->state.conn < Connected )) {
			//WARN("worker: a callback failed! \n");
			if (mdev->state.conn >= Connected)
				drbd_force_state(mdev,NS(conn,NetworkFailure));
			drbd_thread_restart_nowait(&mdev->receiver);
		}
	}

	drbd_wait_ee_list_empty(mdev,&mdev->read_ee);

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
