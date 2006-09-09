/*
-*- linux-c -*-
   drbd_worker.c
   Kernel module for 2.4.x/2.6.x Kernels

   This file is part of drbd by Philipp Reisner.

   Copyright (C) 1999-2006, Philipp Reisner <philipp.reisner@linbit.com>.
   Copyright (C) 2002-2006, Lars Ellenberg <lars.ellenberg@linbit.com>.
   Copyright (C) 2001-2006, LINBIT Information Technologies GmbH.

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
#include "drbd_req.h"

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
	 * return as long as bio->bio_size is positive.  */
	if (bio->bi_size) return 1;

	D_ASSERT(e->block_id != ID_VACANT);

	spin_lock_irqsave(&mdev->req_lock,flags);
	mdev->read_cnt += e->size >> 9;
	list_del(&e->w.list);
	if(list_empty(&mdev->read_ee)) wake_up(&mdev->ee_wait);
	spin_unlock_irqrestore(&mdev->req_lock,flags);

	drbd_chk_io_error(mdev,error);
	drbd_queue_work(&mdev->data.work,&e->w);
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
	drbd_dev *mdev;
	int do_wake;
	int is_syncer_req;

	e = bio->bi_private;
	mdev = e->mdev;

	// see above
	if (bio->bi_size) return 1;

	D_ASSERT(e->block_id != ID_VACANT);

	spin_lock_irqsave(&mdev->req_lock,flags);
	mdev->writ_cnt += e->size >> 9;
	is_syncer_req = is_syncer_block_id(e->block_id);
	list_del(&e->w.list); /* has been on active_ee or sync_ee */
	list_add_tail(&e->w.list,&mdev->done_ee);

	/* No hlist_del_init(&e->colision) here, we did not send the Ack yet,
	 * neither did we wake possibly waiting conflicting requests.
	 * done from "drbd_process_done_ee" or _drbd_clear_done_ee
	 * within the appropriate w.cb (e_end_block) */

	if(!is_syncer_req) mdev->epoch_size++;
	
	do_wake = is_syncer_req
		? list_empty(&mdev->sync_ee)
		: list_empty(&mdev->active_ee);

	if (error) __drbd_chk_io_error(mdev);
	spin_unlock_irqrestore(&mdev->req_lock,flags);

	if (do_wake) wake_up(&mdev->ee_wait);

	wake_asender(mdev);
	dec_local(mdev);
	return 0;
}

/* read, readA or write requests on Primary comming from drbd_make_request
 */
int drbd_endio_pri(struct bio *bio, unsigned int bytes_done, int error)
{
	unsigned long flags;
	drbd_request_t *req=bio->bi_private;
	drbd_dev *mdev = req->mdev;
	drbd_req_event_t what;

	// see above
	if (bio->bi_size) return 1;

	/* to avoid recursion in _req_mod */
	what = error
	       ? (bio_data_dir(bio) == WRITE)
	         ? write_completed_with_error
	         : read_completed_with_error
	       : completed_ok;
	spin_lock_irqsave(&mdev->req_lock,flags);
	_req_mod(req, what);
	spin_unlock_irqrestore(&mdev->req_lock,flags);
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
	D_ASSERT(mdev->bc->dc.on_io_error != PassOn);

	/* the only way this callback is scheduled is from _req_may_be_done,
	 * when it is done and had a local write error, see comments there */
	drbd_req_free(req);

	if(unlikely(cancel)) return 1;

	ok = drbd_io_error(mdev);
	if(unlikely(!ok)) ERR("Sending in w_io_error() failed\n");
	return ok;
}

int w_read_retry_remote(drbd_dev* mdev, struct drbd_work* w,int cancel)
{
	drbd_request_t *req = (drbd_request_t*)w;

	spin_lock_irq(&mdev->req_lock);
	if ( cancel ||
	     mdev->state.conn < Connected ||
	     mdev->state.pdsk <= Inconsistent ) {
		_req_mod(req, send_canceled); /* FIXME freeze? ... */
		spin_unlock_irq(&mdev->req_lock);
		drbd_khelper(mdev,"pri-on-incon-degr"); /* FIXME REALLY? */
		ALERT("WE ARE LOST. Local IO failure, no peer.\n");
		return 1;
	}
	spin_unlock_irq(&mdev->req_lock);

	/* FIXME this is ugly. we should not detach for read io-error,
	 * but try to WRITE the DataReply to the failed location,
	 * to give the disk the chance to relocate that block */
	drbd_io_error(mdev); /* tries to schedule a detach and notifies peer */
	return w_send_read_req(mdev,w,0);
}

int w_resync_inactive(drbd_dev *mdev, struct drbd_work *w, int cancel)
{
	ERR_IF(cancel) return 1;
	ERR("resync inactive, but callback triggered??\n");
	return 0;
}

/* for debug assertion only */
int w_req_cancel_conflict(drbd_dev *mdev, struct drbd_work *w, int cancel)
{
	ERR("w_req_cancel_conflict: this callback should never be called!\n");
	if (cancel) return 1; /* does it matter? */
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

	spin_unlock_irqrestore(&mdev->req_lock,flags);

	if(list_empty(&mdev->resync_work.list)) {
		drbd_queue_work(&mdev->data.work,&mdev->resync_work);
	} else INFO("Avoided requeue of resync_work\n");
}

#define SLEEP_TIME (HZ/10)

int w_make_resync_request(drbd_dev* mdev, struct drbd_work* w,int cancel)
{
	unsigned long bit;
	sector_t sector;
	const sector_t capacity = drbd_get_capacity(mdev->this_bdev);
	int max_segment_size = mdev->rq_queue->max_segment_size;
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
		/* as of now, we are the only user of drbd_bm_find_next */
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
		/* try to find some adjacent bits.
		 * we stop if we have already the maximum req size
		 * or if it the request would cross a 32k boundary
		 * (play more nicely with most raid devices).
		 *
		 * we _do_ care about the agreed-uppon q->max_segment_size
		 * here, as splitting up the requests on the other side is more
		 * difficult.  the consequence is, that on lvm and md and other
		 * "indirect" devices, this is dead code, since
		 * q->max_segment_size will be PAGE_SIZE.
		 */
		for (;;) {
			if (size + BM_BLOCK_SIZE > max_segment_size)
				break;
			if ((sector & ~63ULL) + BM_BIT_TO_SECT(2) <= 64ULL)
				break;
			// do not cross extent boundaries
			if (( (bit+1) & BM_BLOCKS_PER_BM_EXT_MASK ) == 0)
				break;
			/* now, is it actually dirty, after all?
			 * caution, drbd_bm_test_bit is tri-state for some
			 * obscure reason; ( b == 0 ) would get the out-of-band
			 * only accidentally right because of the "oddly sized"
			 * adjustment below */
			if ( drbd_bm_test_bit(mdev,bit+1) != 1 )
				break;
			bit++;
			size += BM_BLOCK_SIZE;
			i++;
		}
		/* if we merged some,
		 * reset the offset to start the next drbd_bm_find_next from */
		if (size > BM_BLOCK_SIZE)
			drbd_bm_set_find(mdev,bit+1);
#endif

		/* adjust very last sectors, in case we are oddly sized */
		if (sector + (size>>9) > capacity) size = (capacity-sector)<<9;
		inc_rs_pending(mdev);
		if(!drbd_send_drequest(mdev,RSDataRequest,
				       sector,size,ID_SYNCER)) {
			ERR("drbd_send_drequest() failed, aborting...\n");
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

	drbd_md_sync(mdev);

	return 1;
}

/**
 * w_e_end_data_req: Send the answer (DataReply) in response to a DataRequest.
 */
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
		/* FIXME we should not detach for read io-errors, in particular
		 * not now: when the peer asked us for our data, we are likely
		 * the only remaining disk... */
		drbd_io_error(mdev);
	}

	dec_unacked(mdev);

	spin_lock_irq(&mdev->req_lock);
	if( drbd_bio_has_active_page(e->private_bio) ) {
		/* This might happen if sendpage() has not finished */
		list_add_tail(&e->w.list,&mdev->net_ee);
	} else {
		drbd_free_ee(mdev,e);
	}
	spin_unlock_irq(&mdev->req_lock);

	if(unlikely(!ok)) ERR("drbd_send_block() failed\n");
	return ok;
}

/**
 * w_e_end_data_req: Send the answer (RSDataReply) to a RSDataRequest.
 */
int w_e_end_rsdata_req(drbd_dev *mdev, struct drbd_work *w, int cancel)
{
	struct Tl_epoch_entry *e = (struct Tl_epoch_entry*)w;
	int ok;

	if(unlikely(cancel)) {
		drbd_free_ee(mdev,e);
		dec_unacked(mdev);
		return 1;
	}

	drbd_rs_complete_io(mdev,e->sector);

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

	spin_lock_irq(&mdev->req_lock);
	if( drbd_bio_has_active_page(e->private_bio) ) {
		/* This might happen if sendpage() has not finished */
		list_add_tail(&e->w.list,&mdev->net_ee);
	} else {
		drbd_free_ee(mdev,e);
	}
	spin_unlock_irq(&mdev->req_lock);

	if(unlikely(!ok)) ERR("drbd_send_block() failed\n");
	return ok;
}

int w_send_barrier(drbd_dev *mdev, struct drbd_work *w, int cancel)
{
	struct drbd_barrier *b = (struct drbd_barrier *)w;
	Drbd_Barrier_Packet *p = &mdev->data.sbuf.Barrier;
	int ok=1;

	if(unlikely(cancel)) return ok;

	down(&mdev->data.mutex);
	p->barrier = b->br_number;
	inc_ap_pending(mdev);
	ok = _drbd_send_cmd(mdev,mdev->data.socket,Barrier,(Drbd_Header*)p,sizeof(*p),0);
	up(&mdev->data.mutex);

	/* pairing dec_ap_pending() happens in got_BarrierAck,
	 * or (on connection loss) in tl_clear.  */

	return ok;
}

int w_send_write_hint(drbd_dev *mdev, struct drbd_work *w, int cancel)
{
	if (cancel) return 1;
	return drbd_send_short_cmd(mdev,UnplugRemote);
}

/**
 * w_send_dblock: Send a mirrored write request.
 */
int w_send_dblock(drbd_dev *mdev, struct drbd_work *w, int cancel)
{
	drbd_request_t *req = (drbd_request_t *)w;
	int ok;

	if (unlikely(cancel)) {
		req_mod(req, send_canceled);
		return 1;
	}

	ok = drbd_send_dblock(mdev,req);
	req_mod(req,ok ? handed_over_to_network : send_failed);

	return ok;
}

/**
 * w_send_read_req: Send a read requests.
 */
int w_send_read_req(drbd_dev *mdev, struct drbd_work *w, int cancel)
{
	drbd_request_t *req = (drbd_request_t *)w;
	int ok;

	if (unlikely(cancel)) {
		req_mod(req, send_canceled);
		return 1;
	}

	ok = drbd_send_drequest(mdev, DataRequest, req->sector, req->size,
				(unsigned long)req);

	if (!ok) {
		/* ?? we set Timeout or BrokenPipe in drbd_send() */
		if (mdev->state.conn >= Connected) 
			drbd_force_state(mdev,NS(conn,NetworkFailure));
		drbd_thread_restart_nowait(&mdev->receiver);
		/* req_mod(req, send_failed); we should not fail it here,
		 * we might have to "freeze" on disconnect.
		 * handled by req_mod(req, connection_lost_while_pending);
		 * in drbd_fail_pending_reads soon enough. */
	}

	return ok;
}

/* FIXME how should freeze-io be handled? */
STATIC void drbd_fail_pending_reads(drbd_dev *mdev)
{
	struct hlist_head *slot;
	struct hlist_node *n;
	drbd_request_t * req;
	struct list_head *le;
	LIST_HEAD(workset);
	int i;

	/*
	 * Application READ requests
	 */
	spin_lock_irq(&mdev->req_lock);
	for(i=0;i<APP_R_HSIZE;i++) {
		slot = mdev->app_reads_hash+i;
		hlist_for_each_entry(req, n, slot, colision) {
			list_add(&req->w.list, &workset);
		}
	}
	memset(mdev->app_reads_hash,0,APP_R_HSIZE*sizeof(void*));

	while(!list_empty(&workset)) {
		le = workset.next;
		req = list_entry(le, drbd_request_t, w.list);
		list_del(le);

		_req_mod(req, connection_lost_while_pending);
	}
	spin_unlock_irq(&mdev->req_lock);
}

/**
 * w_disconnect clean up everything, and restart the receiver.
 */
int w_disconnect(drbd_dev *mdev, struct drbd_work *w, int cancel)
{
	D_ASSERT(cancel);

	down(&mdev->data.mutex);
	/* By grabbing the sock_mutex we make sure that no one
	   uses the socket right now. */
	drbd_free_sock(mdev);
	up(&mdev->data.mutex);

	drbd_fail_pending_reads(mdev);
	drbd_rs_cancel_all(mdev);

	// primary
	clear_bit(ISSUE_BARRIER,&mdev->flags);

	if(!mdev->state.susp) {
		tl_clear(mdev);
		D_ASSERT(mdev->oldest_barrier->n_req == 0);

		if(atomic_read(&mdev->ap_pending_cnt)) {
			ERR("ap_pending_cnt = %d\n",
			    atomic_read(&mdev->ap_pending_cnt));
			atomic_set(&mdev->ap_pending_cnt,0);
		}
	}

	D_ASSERT(atomic_read(&mdev->pp_in_use) == 0);
	D_ASSERT(list_empty(&mdev->read_ee));
	D_ASSERT(list_empty(&mdev->active_ee)); // done here
	D_ASSERT(list_empty(&mdev->sync_ee)); // done here
	D_ASSERT(list_empty(&mdev->done_ee)); // done here

	mdev->rs_total=0;

	if(atomic_read(&mdev->unacked_cnt)) {
		ERR("unacked_cnt = %d\n",atomic_read(&mdev->unacked_cnt));
		atomic_set(&mdev->unacked_cnt,0);
	}

	/* We do not have data structures that would allow us to
	   get the rs_pending_cnt down to 0 again.
	   * On SyncTarget we do not have any data structures describing
	     the pending RSDataRequest's we have sent.
	   * On SyncSource there is no data structure that tracks
	     the RSDataReply blocks that we sent to the SyncTarget.
	   And no, it is not the sum of the reference counts in the
	   resync_LRU. The resync_LRU tracks the whole operation including
           the disk-IO, while the rs_pending_cnt only tracks the blocks
	   on the fly. */
	atomic_set(&mdev->rs_pending_cnt,0);
	wake_up(&mdev->cstate_wait);

	if ( mdev->p_uuid ) {
		kfree(mdev->p_uuid);
		mdev->p_uuid = NULL;
	}

	INFO("Connection closed\n");

	if(w) kfree(w);

	return 1;
}

STATIC void drbd_global_lock(void)
{
	drbd_dev *mdev;
	int i;

	local_irq_disable();
	for (i=0; i < minor_count; i++) {
		if(!(mdev = minor_to_mdev(i))) continue;
		spin_lock(&mdev->req_lock);
	}
}

STATIC void drbd_global_unlock(void)
{
	drbd_dev *mdev;
	int i;

	for (i=0; i < minor_count; i++) {
		if(!(mdev = minor_to_mdev(i))) continue;
		spin_unlock(&mdev->req_lock);
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
	return r != SS_NothingToDo;
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

	return r != SS_NothingToDo;
}

STATIC int _drbd_may_sync_now(drbd_dev *mdev)
{
	drbd_dev *odev = mdev;

	while(1) {
		if( odev->sync_conf.after == -1 ) return 1;
		odev = minor_to_mdev(odev->sync_conf.after);
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
		if( !(odev = minor_to_mdev(i)) ) continue;
		if (! _drbd_may_sync_now(odev)) {
			rv |= _drbd_rs_pause(odev,AfterDependency);
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
		if( !(odev = minor_to_mdev(i)) ) continue;
		if ( odev->state.conn == PausedSyncS ||
		     odev->state.conn == PausedSyncT ) {
			if (_drbd_may_sync_now(odev)) {
				rv |= _drbd_rs_resume(odev,AfterDependency);
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
	w->cb = w_resync_inactive;
	drbd_global_unlock();

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
 * Note, this function might bring you directly into one of the
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

	if ( r == SS_Success ) {
		mdev->rs_total     =
		mdev->rs_mark_left = drbd_bm_total_weight(mdev);
		mdev->rs_paused    = 0;
		mdev->rs_start     =
		mdev->rs_mark_time = jiffies;
		_drbd_pause_after(mdev);
	}
	drbd_global_unlock();

	if ( r == SS_Success ) {
		after_state_ch(mdev,os,ns,ChgStateVerbose);

		INFO("Began resync as %s (will sync %lu KB [%lu bits set]).\n",
		     conns_to_name(ns.conn),
		     (unsigned long) mdev->rs_total << (BM_BLOCK_SIZE_B-10),
		     (unsigned long) mdev->rs_total);

		if ( mdev->rs_total == 0 ) {
			drbd_resync_finished(mdev);
			return;
		}

		if( ns.conn == SyncTarget ) {
			D_ASSERT(!test_bit(STOP_SYNC_TIMER,&mdev->flags));
			mod_timer(&mdev->resync_timer,jiffies);
		}

		drbd_md_sync(mdev);
	}
}

int drbd_worker(struct Drbd_thread *thi)
{
	drbd_dev *mdev = thi->mdev;
	struct drbd_work *w = 0;
	LIST_HEAD(work_list);
	int intr,i;

	sprintf(current->comm, "drbd%d_worker", mdev_to_minor(mdev));

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
		spin_lock_irq(&mdev->data.work.q_lock);
		ERR_IF(list_empty(&mdev->data.work.q)) {
			/* something terribly wrong in our logic.
			 * we were able to down() the semaphore,
			 * but the list is empty... doh.
			 *
			 * what is the best thing to do now?
			 * try again from scratch, restarting the receiver,
			 * asender, whatnot? could break even more ugly,
			 * e.g. when we are primary, but no good local data.
			 *
			 * I'll try to get away just starting over this loop.
			 */
			spin_unlock_irq(&mdev->data.work.q_lock);
			continue;
		}
		w = list_entry(mdev->data.work.q.next,struct drbd_work,list);
		list_del_init(&w->list);
		spin_unlock_irq(&mdev->data.work.q_lock);

		if(!w->cb(mdev,w, mdev->state.conn < Connected )) {
			//WARN("worker: a callback failed! \n");
			if (mdev->state.conn >= Connected)
				drbd_force_state(mdev,NS(conn,NetworkFailure));
			drbd_thread_restart_nowait(&mdev->receiver);
		}
	}

	drbd_wait_ee_list_empty(mdev,&mdev->read_ee);

	/* When we terminate a resync process, either because it finished
	 * sucessfully, or because (like in this case here) we lost
	 * communications, we need to "w_resume_next_sg".
	 * We cannot use del_timer_sync from within _set_cstate, and since the
	 * resync timer may still be scheduled and would then trigger anyways,
	 * we set the STOP_SYNC_TIMER bit, and schedule the timer for immediate
	 * execution from within _set_cstate().
	 * The timer should then clear that bit and queue w_resume_next_sg.
	 *
	 * This is fine for the normal "resync finished" case.
	 *
	 * In this case (worker thread beeing stopped), there is a race:
	 * we cannot be sure that the timer already triggered.
	 *
	 * So we del_timer_sync here, and check that "STOP_SYNC_TIMER" bit.
	 * if it is still set, we queue w_resume_next_sg anyways,
	 * just to be sure.
	 */

	del_timer_sync(&mdev->resync_timer);
	/* possible paranoia check: the STOP_SYNC_TIMER bit should be set
	 * if and only if del_timer_sync returns true ... */

	spin_lock_irq(&mdev->data.work.q_lock);
	if (test_and_clear_bit(STOP_SYNC_TIMER,&mdev->flags)) {
		mdev->resync_work.cb = w_resume_next_sg;
		if (list_empty(&mdev->resync_work.list))
			drbd_queue_work(&mdev->data.work,&mdev->resync_work);
		// else: already queued
	} else {
		/* timer already consumed that bit, or it was never set */
		if (list_empty(&mdev->resync_work.list)) {
			/* not queued, should be inactive */
			ERR_IF (mdev->resync_work.cb != w_resync_inactive)
				mdev->resync_work.cb = w_resync_inactive;
		} else {
			/* still queued; should be w_resume_next_sg */
			ERR_IF (mdev->resync_work.cb != w_resume_next_sg)
				mdev->resync_work.cb = w_resume_next_sg;
		}
	}

	i = 0;
  again:
	list_splice_init(&mdev->data.work.q,&work_list);
	spin_unlock_irq(&mdev->data.work.q_lock);

	while(!list_empty(&work_list)) {
		w = list_entry(work_list.next, struct drbd_work,list);
		list_del_init(&w->list);
		w->cb(mdev,w,1);
		i++; /* dead debugging code */
	}

	spin_lock_irq(&mdev->data.work.q_lock);
	ERR_IF(!list_empty(&mdev->data.work.q))
		goto again;
	sema_init(&mdev->data.work.s,0);
	/* DANGEROUS race: if someone did queue his work within the spinlock,
	 * but up() ed outside the spinlock, we could get an up() on the
	 * semaphore without corresponding list entry.
	 * So don't do that.
	 */
	spin_unlock_irq(&mdev->data.work.q_lock);

	INFO("worker terminated\n");

	return 0;
}
