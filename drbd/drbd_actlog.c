/*
-*- linux-c -*-
   drbd_actlog.c
   Kernel module for 2.4.x/2.6.x Kernels

   This file is part of drbd by Philipp Reisner.

   Copyright (C) 2003-2006, Philipp Reisner <philipp.reisner@linbit.com>.
   Copyright (C) 2003-2006, Lars Ellenberg <lars.ellenberg@linbit.com>.
   Copyright (C) 2003-2006, LINBIT Information Technologies GmbH.

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

#include <linux/slab.h>
#include <linux/drbd.h>
#include "drbd_int.h"

/* This is what I like so much about the linux kernel:
 * if you have a close look, you can almost always reuse code by someone else
 * ;)
 * this is mostly from drivers/md/md.c
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
STATIC int _drbd_md_sync_page_io(drbd_dev *mdev, struct page *page, 
				 sector_t sector, int rw, int size)
{
	struct buffer_head bh;
	struct completion event;
	int ok;

	init_completion(&event);
	init_buffer(&bh, drbd_md_io_complete, &event);
	bh.b_rdev = mdev->md_bdev;
	bh.b_rsector = sector;
	bh.b_state = (1 << BH_Req) | (1 << BH_Mapped) | (1 << BH_Lock);
	bh.b_size = size; 
	bh.b_page = page;
	bh.b_reqnext = NULL;
	bh.b_data = page_address(page);
	generic_make_request(rw, &bh);

	run_task_queue(&tq_disk);
	wait_for_completion(&event);

	ok = test_bit(BH_Uptodate, &bh.b_state);

	return ok;
}
#else
STATIC int _drbd_md_sync_page_io(drbd_dev *mdev, struct page *page, 
				 sector_t sector, int rw, int size)
{
	struct bio *bio = bio_alloc(GFP_NOIO, 1);
	struct completion event;
	int ok;

	bio->bi_bdev = mdev->md_bdev;
	bio->bi_sector = sector;
	bio_add_page(bio, page, size, 0);
	init_completion(&event);
	bio->bi_private = &event;
	bio->bi_end_io = drbd_md_io_complete;

#ifdef BIO_RW_SYNC
	submit_bio(rw | (1 << BIO_RW_SYNC), bio);
#else
	submit_bio(rw, bio);
	drbd_blk_run_queue(bdev_get_queue(mdev->md_bdev));
#endif
	wait_for_completion(&event);

	ok = test_bit(BIO_UPTODATE, &bio->bi_flags);
	bio_put(bio);
	return ok;
}
#endif

int drbd_md_sync_page_io(drbd_dev *mdev, sector_t sector, int rw)
{
	int hardsect,mask,ok,offset=0;
	const sector_t capacity = drbd_get_capacity(mdev->this_bdev);
	struct page *iop = mdev->md_io_page;

	D_ASSERT(semaphore_is_locked(&mdev->md_io_mutex));

	if (!mdev->md_bdev) {
		if (test_bit(DISKLESS,&mdev->flags)) return 0;
		if (DRBD_ratelimit(5*HZ,5)) {
			ERR("mdev->md_bdev==NULL\n");
			dump_stack();
		}
		return 0;
	}


	hardsect = drbd_get_hardsect(mdev->md_bdev);

	// in case hardsect != 512 [ s390 only? ]
	if( hardsect != MD_HARDSECT ) {
		if(!mdev->md_io_tmpp) {
			struct page *page = alloc_page(GFP_NOIO);
			if(!page) return 0;

			WARN("Meta data's bdev hardsect_size != %d\n",
			     MD_HARDSECT);
			WARN("Workaround engaged (has performace impact).\n");

			mdev->md_io_tmpp = page;
		}

		mask = ( hardsect / MD_HARDSECT ) - 1;
		D_ASSERT( mask == 1 || mask == 3 || mask == 7 );
		D_ASSERT( hardsect == (mask+1) * MD_HARDSECT );
		offset = sector & mask;
		sector = sector & ~mask;
		iop = mdev->md_io_tmpp;

		if (rw == WRITE) {
			void *p = page_address(mdev->md_io_page);
			void *hp = page_address(mdev->md_io_tmpp);

			ok = _drbd_md_sync_page_io(mdev,iop,
						   sector,READ,hardsect);

			if (unlikely(!ok)) return 0;

			memcpy(hp + offset*MD_HARDSECT , p, MD_HARDSECT);
		}
	}

#if DUMP_MD >= 3
	INFO("%s [%d]:%s(,%llu,%s)\n",
	     current->comm, current->pid, __func__,
	     (unsigned long long)sector, rw ? "WRITE" : "READ");
#endif

	if (sector < drbd_md_ss(mdev)  ||
	    sector > drbd_md_ss(mdev)+MD_BM_OFFSET+BM_SECT_TO_EXT(capacity)) {
		ALERT("%s [%d]:%s(,%llu,%s) out of range md access!\n",
		     current->comm, current->pid, __func__,
		     (unsigned long long)sector, rw ? "WRITE" : "READ");
	}

	ok = _drbd_md_sync_page_io(mdev,iop,sector,rw,hardsect);
	if (unlikely(!ok)) {
		ERR("drbd_md_sync_page_io(,%llu,%s) failed!\n",
		    (unsigned long long)sector,rw ? "WRITE" : "READ");
	}

	if( hardsect != MD_HARDSECT && rw == READ ) {
		void *p = page_address(mdev->md_io_page);
		void *hp = page_address(mdev->md_io_tmpp);

		memcpy(p, hp + offset*MD_HARDSECT, MD_HARDSECT);
	}

	return ok;
}


struct __attribute__((packed)) al_transaction {
	u32       magic;
	u32       tr_number;
	// u32       tr_generation; //TODO
	struct __attribute__((packed)) {
		u32 pos;
		u32 extent; } updates[1 + AL_EXTENTS_PT];
	u32       xor_sum;
       // I do not believe that all storage medias can guarantee atomic
       // 512 byte write operations. When the journal is read, only
       // transactions with correct xor_sums are considered.
};     // sizeof() = 512 byte


struct update_odbm_work {
	struct drbd_work w;
	unsigned int enr;
};

struct update_al_work {
	struct drbd_work w;
	struct lc_element * al_ext;
	struct completion event;
	unsigned int enr;
};

STATIC int w_al_write_transaction(struct Drbd_Conf *, struct drbd_work *, int);

static inline
struct lc_element* _al_get(struct Drbd_Conf *mdev, unsigned int enr)
{
	struct lc_element *al_ext;
	struct bm_extent  *bm_ext;
	unsigned long     al_flags=0;

	spin_lock_irq(&mdev->al_lock);
	bm_ext = (struct bm_extent*) lc_find(mdev->resync,enr/AL_EXT_PER_BM_SECT);
	if (unlikely(bm_ext!=NULL)) {
		if(test_bit(BME_NO_WRITES,&bm_ext->flags)) {
			spin_unlock_irq(&mdev->al_lock);
			//INFO("Delaying app write until sync read is done\n");
			return 0;
		}
	}
	al_ext   = lc_get(mdev->act_log,enr);
	al_flags = mdev->act_log->flags;
	spin_unlock_irq(&mdev->al_lock);

	/*
	if (!al_ext) {
		if (al_flags & LC_STARVING)
			WARN("Have to wait for LRU element (AL too small?)\n");
		if (al_flags & LC_DIRTY)
			WARN("Ongoing AL update (AL device too slow?)\n");
	}
	*/

	return al_ext;
}

void drbd_al_begin_io(struct Drbd_Conf *mdev, sector_t sector)
{
	unsigned int enr = (sector >> (AL_EXTENT_SIZE_B-9));
	struct lc_element *al_ext;
	struct update_al_work al_work;

	D_ASSERT(atomic_read(&mdev->local_cnt)>0);
	wait_event(mdev->al_wait, (al_ext = _al_get(mdev,enr)) );

	if (al_ext->lc_number != enr) {
		// We have to do write an transaction to AL.
		unsigned int evicted;

		evicted = al_ext->lc_number;

		if(mdev->cstate < Connected && evicted != LC_FREE ) {
			drbd_bm_write_sect(mdev, evicted/AL_EXT_PER_BM_SECT );
		}

		/* drbd_al_write_transaction(mdev,al_ext,enr);
		   generic_make_request() are serialized on the 
		   current->bio_tail list now. Therefore we have
		   to deligate writing something to AL to the
		   worker thread. */
		init_completion(&al_work.event);
		al_work.al_ext = al_ext;
		al_work.enr = enr;
		al_work.w.cb = w_al_write_transaction;
		drbd_queue_work_front(mdev,&mdev->data.work,&al_work.w);
		wait_for_completion(&al_work.event);
		
		mdev->al_writ_cnt++;

		/*
		DUMPI(al_ext->lc_number);
		DUMPI(mdev->act_log->new_number);
		*/
		spin_lock_irq(&mdev->al_lock);
		lc_changed(mdev->act_log,al_ext);
		spin_unlock_irq(&mdev->al_lock);
		wake_up(&mdev->al_wait);
	}
}

void drbd_al_complete_io(struct Drbd_Conf *mdev, sector_t sector)
{
	unsigned int enr = (sector >> (AL_EXTENT_SIZE_B-9));
	struct lc_element *extent;
	unsigned long flags;

	spin_lock_irqsave(&mdev->al_lock,flags);

	extent = lc_find(mdev->act_log,enr);

	if(!extent) {
		spin_unlock_irqrestore(&mdev->al_lock,flags);
		ERR("al_complete_io() called on inactive extent %u\n",enr);
		return;
	}

	if( lc_put(mdev->act_log,extent) == 0 ) {
		wake_up(&mdev->al_wait);
	}

	spin_unlock_irqrestore(&mdev->al_lock,flags);
}

STATIC int
w_al_write_transaction(struct Drbd_Conf *mdev, struct drbd_work *w, int unused)
{
	int i,n,mx;
	unsigned int extent_nr;
	struct al_transaction* buffer;
	sector_t sector;
	u32 xor_sum=0;

	struct lc_element *updated = ((struct update_al_work*)w)->al_ext;
	unsigned int new_enr = ((struct update_al_work*)w)->enr;

	down(&mdev->md_io_mutex); // protects md_io_buffer, al_tr_cycle, ...
	buffer = (struct al_transaction*)page_address(mdev->md_io_page);

	buffer->magic = __constant_cpu_to_be32(DRBD_MAGIC);
	buffer->tr_number = cpu_to_be32(mdev->al_tr_number);

	n = lc_index_of(mdev->act_log, updated);

	buffer->updates[0].pos = cpu_to_be32(n);
	buffer->updates[0].extent = cpu_to_be32(new_enr);

#if 0	/* Use this printf with the test_al.pl program */
	ERR("T%03d S%03d=E%06d\n", mdev->al_tr_number,n,new_enr);
#endif

	xor_sum ^= new_enr;

	mx = min_t(int,AL_EXTENTS_PT,
		   mdev->act_log->nr_elements - mdev->al_tr_cycle);
	for(i=0;i<mx;i++) {
		extent_nr = lc_entry(mdev->act_log,
				     mdev->al_tr_cycle+i)->lc_number;
		buffer->updates[i+1].pos = cpu_to_be32(mdev->al_tr_cycle+i);
		buffer->updates[i+1].extent = cpu_to_be32(extent_nr);
		xor_sum ^= extent_nr;
	}
	for(;i<AL_EXTENTS_PT;i++) {
		buffer->updates[i+1].pos = __constant_cpu_to_be32(-1);
		buffer->updates[i+1].extent = __constant_cpu_to_be32(LC_FREE);
		xor_sum ^= LC_FREE;
	}
	mdev->al_tr_cycle += AL_EXTENTS_PT;
	if(mdev->al_tr_cycle >= mdev->act_log->nr_elements) mdev->al_tr_cycle=0;

	buffer->xor_sum = cpu_to_be32(xor_sum);


	sector = drbd_md_ss(mdev) + MD_AL_OFFSET + mdev->al_tr_pos ;

	if(!drbd_md_sync_page_io(mdev,sector,WRITE)) {
		drbd_chk_io_error(mdev, 1);
		drbd_io_error(mdev);
	}

	if( ++mdev->al_tr_pos > div_ceil(mdev->act_log->nr_elements,AL_EXTENTS_PT) ) {
		mdev->al_tr_pos=0;
	}
	D_ASSERT(mdev->al_tr_pos < MD_AL_MAX_SIZE);
	mdev->al_tr_number++;

	up(&mdev->md_io_mutex);

	complete(&((struct update_al_work*)w)->event);

	return 1;
}

/**
 * drbd_al_read_tr: Reads a single transaction record form the 
 * on disk activity log.
 * Returns -1 on IO error, 0 on checksum error and 1 if it is a valid
 * record.
 */
STATIC int drbd_al_read_tr(struct Drbd_Conf *mdev,
			   struct al_transaction* b,
			   int index)
{
	sector_t sector;
	int rv,i;
	u32 xor_sum=0;

	sector = drbd_md_ss(mdev) + MD_AL_OFFSET + index;

	if(!drbd_md_sync_page_io(mdev,sector,READ)) {
		drbd_chk_io_error(mdev, 1);
		drbd_io_error(mdev);
		return -1;
	}

	rv = ( be32_to_cpu(b->magic) == DRBD_MAGIC );

	for(i=0;i<AL_EXTENTS_PT+1;i++) {
		xor_sum ^= be32_to_cpu(b->updates[i].extent);
	}
	rv &= (xor_sum == be32_to_cpu(b->xor_sum));

	return rv;
}

/**
 * drbd_al_read_log: Restores the activity log from its on disk
 * representation. Returns 1 on success, returns 0 when 
 * reading the log failed due to IO errors.
 */
int drbd_al_read_log(struct Drbd_Conf *mdev)
{
	struct al_transaction* buffer;
	int from=-1,to=-1,i,cnr, overflow=0,rv;
	u32 from_tnr=-1, to_tnr=0;
	int active_extents=0;
	int transactions=0;
	int mx;

	mx = div_ceil(mdev->act_log->nr_elements,AL_EXTENTS_PT);

	/* lock out all other meta data io for now,
	 * and make sure the page is mapped.
	 */
	down(&mdev->md_io_mutex);
	buffer = page_address(mdev->md_io_page);

	// Find the valid transaction in the log
	for(i=0;i<=mx;i++) {
		rv = drbd_al_read_tr(mdev,buffer,i);
		if(rv == 0) continue;
		if(rv == -1) {
			up(&mdev->md_io_mutex);
			return 0;
		}
		cnr = be32_to_cpu(buffer->tr_number);
		// INFO("index %d valid tnr=%d\n",i,cnr);

		if(cnr == -1) overflow=1;

		if(cnr < from_tnr && !overflow) {
			from = i;
			from_tnr = cnr;
		}
		if(cnr > to_tnr) {
			to = i;
			to_tnr = cnr;
		}
	}

	if(from == -1 || to == -1) {
		WARN("No usable activity log found.\n");

		up(&mdev->md_io_mutex);
		return 1;
	}

	// Read the valid transactions.
	// INFO("Reading from %d to %d.\n",from,to);

	/* this should better be handled by a for loop, no?
	 */
	i=from;
	while(1) {
		int j,pos;
		unsigned int extent_nr;
		unsigned int trn;

		rv = drbd_al_read_tr(mdev,buffer,i);
		ERR_IF(rv == 0) goto cancel;
		if(rv == -1) {
			up(&mdev->md_io_mutex);
			return 0;
		}

		trn=be32_to_cpu(buffer->tr_number);

		spin_lock_irq(&mdev->al_lock);

		/* This loop runs backwards because in the cyclic 
		   elements there might be an old version of the
		   updated element (in slot 0). So the element in slot 0
		   can overwrite old versions. */
		for(j=AL_EXTENTS_PT;j>=0;j--) {
			pos = be32_to_cpu(buffer->updates[j].pos);
			extent_nr = be32_to_cpu(buffer->updates[j].extent);

			if(extent_nr == LC_FREE) continue;

		       //if(j<3) INFO("T%03d S%03d=E%06d\n",trn,pos,extent_nr);
			lc_set(mdev->act_log,extent_nr,pos);
			active_extents++;
		}
		spin_unlock_irq(&mdev->al_lock);

		transactions++;

	cancel:
		if( i == to) break;
		i++;
		if( i > mx ) i=0;
	}

	mdev->al_tr_number = to_tnr+1;
	mdev->al_tr_pos = to;
	if( ++mdev->al_tr_pos > div_ceil(mdev->act_log->nr_elements,AL_EXTENTS_PT) ) {
		mdev->al_tr_pos=0;
	}

	/* ok, we are done with it */
	up(&mdev->md_io_mutex);

	INFO("Found %d transactions (%d active extents) in activity log.\n",
	     transactions,active_extents);

	return 1;
}

/**
 * drbd_al_to_on_disk_bm:
 * Writes the areas of the bitmap which are covered by the AL.
 * called when we detach (unconfigure) local storage,
 * or when we go from Primary to Secondary state.
 */
void drbd_al_to_on_disk_bm(struct Drbd_Conf *mdev)
{
	int i;
	unsigned int enr;

	wait_event(mdev->al_wait, lc_try_lock(mdev->act_log));

	i=inc_local_md_only(mdev);
	D_ASSERT( i ); // Assertions should not have side effects.
	// I do not want to have D_ASSERT( inc_local_md_only(mdev) );

	for(i=0;i<mdev->act_log->nr_elements;i++) {
		enr = lc_entry(mdev->act_log,i)->lc_number;
		if(enr == LC_FREE) continue;
		/* TODO encapsulate and optimize within drbd_bitmap
		 * currently, if we have al-extents 16..19 active,
		 * sector 4 will be written four times! */
		drbd_bm_write_sect(mdev, enr/AL_EXT_PER_BM_SECT );
	}

	lc_unlock(mdev->act_log);
	wake_up(&mdev->al_wait);
	dec_local(mdev);
}

/**
 * drbd_al_apply_to_bm: Sets the bits in the bitmap that are described
 * by the active extents of the AL.
 */
void drbd_al_apply_to_bm(struct Drbd_Conf *mdev)
{
	unsigned int enr;
	unsigned long add=0;
	char ppb[10];
	int i;

	wait_event(mdev->al_wait, lc_try_lock(mdev->act_log));

	for(i=0;i<mdev->act_log->nr_elements;i++) {
		enr = lc_entry(mdev->act_log,i)->lc_number;
		if(enr == LC_FREE) continue;
		add += drbd_bm_ALe_set_all(mdev, enr);
	}

	lc_unlock(mdev->act_log);
	wake_up(&mdev->al_wait);

	INFO("Marked additional %s as out-of-sync based on AL.\n",
	     ppsize(ppb,Bit2KB(add)));
}

static inline int _try_lc_del(struct Drbd_Conf *mdev,struct lc_element *al_ext)
{
	int rv;

	spin_lock_irq(&mdev->al_lock);
	rv = (al_ext->refcnt == 0);
	if(likely(rv)) lc_del(mdev->act_log,al_ext);
	spin_unlock_irq(&mdev->al_lock);

	if(unlikely(!rv)) INFO("Waiting for extent in drbd_al_shrink()\n");

	return rv;
}

/**
 * drbd_al_shrink: Removes all active extents form the AL. (but does not
 * write any transactions)
 * You need to lock mdev->act_log with lc_try_lock() / lc_unlock()
 */
void drbd_al_shrink(struct Drbd_Conf *mdev)
{
	struct lc_element *al_ext;
	int i;

	D_ASSERT( test_bit(__LC_DIRTY,&mdev->act_log->flags) );

	for(i=0;i<mdev->act_log->nr_elements;i++) {
		al_ext = lc_entry(mdev->act_log,i);
		if(al_ext->lc_number == LC_FREE) continue;
		wait_event(mdev->al_wait, _try_lc_del(mdev,al_ext));
	}

	wake_up(&mdev->al_wait);
}

STATIC int w_update_odbm(drbd_dev *mdev, struct drbd_work *w, int unused)
{
	struct update_odbm_work *udw = (struct update_odbm_work*)w;

	if( !inc_local_md_only(mdev) ) {
		if (DRBD_ratelimit(5*HZ,5))
			WARN("Can not update on disk bitmap, local IO disabled.\n");
		return 1;
	}

	drbd_bm_write_sect(mdev, udw->enr );
	dec_local(mdev);

	kfree(udw);

	if(drbd_bm_total_weight(mdev) == 0 &&
	   ( mdev->cstate == SyncSource || mdev->cstate == SyncTarget ||
	     mdev->cstate == PausedSyncS || mdev->cstate == PausedSyncT ) ) {
		D_ASSERT( mdev->resync_work.cb == w_resync_inactive );
		drbd_bm_lock(mdev);
		drbd_resync_finished(mdev);
		drbd_bm_unlock(mdev);
	}

	return 1;
}


/* ATTENTION. The AL's extents are 4MB each, while the extents in the  *
 * resync LRU-cache are 16MB each.                                     *
 *
 * TODO will be obsoleted once we have a caching lru of the on disk bitmap
 */
STATIC void drbd_try_clear_on_disk_bm(struct Drbd_Conf *mdev,sector_t sector,
				      int cleared)
{
	struct list_head *le, *tmp;
	struct bm_extent* ext;
	struct update_odbm_work * udw;

	unsigned int enr;

	MUST_HOLD(&mdev->al_lock);

	// I simply assume that a sector/size pair never crosses
	// a 16 MB extent border. (Currently this is true...)
	enr = BM_SECT_TO_EXT(sector);

	ext = (struct bm_extent *) lc_get(mdev->resync,enr);
	if (ext) {
		if( ext->lce.lc_number == enr) {
			ext->rs_left -= cleared;
			if (ext->rs_left < 0) {
				ERR("BAD! sector=%lu enr=%u rs_left=%d cleared=%d\n",
				     (unsigned long)sector,
				     ext->lce.lc_number, ext->rs_left, cleared);
				// FIXME brrrgs. should never happen!
				_set_cstate(mdev,StandAlone);
				drbd_thread_stop_nowait(&mdev->receiver);
				return;
			}
		} else {
			//WARN("Recounting sectors in %d (resync LRU too small?)\n", enr);
			// This element should be in the cache
			// since drbd_rs_begin_io() pulled it already in.
			int rs_left = drbd_bm_e_weight(mdev,enr);
			if (ext->flags != 0) {
				WARN("changing resync lce: %d[%u;%02lx]"
				     " -> %d[%u;00]\n",
				     ext->lce.lc_number, ext->rs_left,
				     ext->flags, enr, rs_left);
				ext->flags = 0;
			}
			ext->rs_left = rs_left;
			lc_changed(mdev->resync,&ext->lce);
		}
		lc_put(mdev->resync,&ext->lce);
		// no race, we are within the al_lock!
	} else {
		ERR("lc_get() failed! locked=%d/%d flags=%lu\n",
		    atomic_read(&mdev->resync_locked), 
		    mdev->resync->nr_elements,
		    mdev->resync->flags);
	}

	list_for_each_safe(le,tmp,&mdev->resync->lru) {
		ext=(struct bm_extent *)list_entry(le,struct lc_element,list);
		if(ext->rs_left == 0) {
			udw=kmalloc(sizeof(*udw),GFP_ATOMIC);
			if(!udw) {
				WARN("Could not kmalloc an udw\n");
				break;
			}
			udw->enr = ext->lce.lc_number;
			udw->w.cb = w_update_odbm;
			drbd_queue_work_front(mdev,&mdev->data.work,&udw->w);
			if (ext->flags != 0) {
				WARN("deleting resync lce: %d[%u;%02lx]\n",
				     ext->lce.lc_number, ext->rs_left,
				     ext->flags);
				ext->flags = 0;
			}
			lc_del(mdev->resync,&ext->lce);
		}
	}
}

/* clear the bit corresponding to the piece of storage in question:
 * size byte of data starting from sector.  Only clear a bits of the affected
 * one ore more _aligned_ BM_BLOCK_SIZE blocks.
 *
 * called by worker on SyncTarget and receiver on SyncSource.
 *
 */
void __drbd_set_in_sync(drbd_dev* mdev, sector_t sector, int size, const char* file, const unsigned int line)
{
	/* Is called from worker and receiver context _only_ */
	unsigned long sbnr,ebnr,lbnr,bnr;
	unsigned long count = 0;
	sector_t esector, nr_sectors;
	int strange_state,wake_up=0;

	strange_state = (mdev->cstate <= Connected) ||
	                test_bit(DISKLESS,&mdev->flags) ||
	                test_bit(PARTNER_DISKLESS,&mdev->flags);
	if (strange_state) {
		ERR("%s:%d: %s flags=0x%02lx\n", file , line ,
				cstate_to_name(mdev->cstate), mdev->flags);
	}

	if (size <= 0 || (size & 0x1ff) != 0 || size > PAGE_SIZE) {
		ERR("drbd_set_in_sync: sector=%lu size=%d nonsense!\n",
				(unsigned long)sector,size);
		return;
	}
	nr_sectors = drbd_get_capacity(mdev->this_bdev);
	esector = sector + (size>>9) -1;

	ERR_IF(sector >= nr_sectors) return;
	ERR_IF(esector >= nr_sectors) esector = (nr_sectors-1);

	lbnr = BM_SECT_TO_BIT(nr_sectors-1);

	/* we clear it (in sync).
	 * round up start sector, round down end sector.  we make sure we only
	 * clear full, alligned, BM_BLOCK_SIZE (4K) blocks */
	if (unlikely(esector < BM_SECT_PER_BIT-1)) {
		return;
	} else if (unlikely(esector == (nr_sectors-1))) {
		ebnr = lbnr;
	} else {
		ebnr = BM_SECT_TO_BIT(esector - (BM_SECT_PER_BIT-1));
	}
	sbnr = BM_SECT_TO_BIT(sector + BM_SECT_PER_BIT-1);

#ifdef DUMP_EACH_PACKET
	INFO("drbd_set_in_sync: sector=%lu size=%d sbnr=%lu ebnr=%lu\n",
			(unsigned long)sector, size, sbnr, ebnr);
#endif

	if (sbnr > ebnr) return;

	/*
	 * ok, (capacity & 7) != 0 sometimes, but who cares...
	 * we count rs_{total,left} in bits, not sectors.
	 */
	spin_lock_irq(&mdev->al_lock);
	for(bnr=sbnr; bnr <= ebnr; bnr++) {
		if (drbd_bm_clear_bit(mdev,bnr)) count++;
	}
	if (count) {
		// we need the lock for drbd_try_clear_on_disk_bm
		if(jiffies - mdev->rs_mark_time > HZ*10) {
			/* should be roling marks, but we estimate only anyways. */
			if( mdev->rs_mark_left != drbd_bm_total_weight(mdev)) {
				mdev->rs_mark_time =jiffies;
				mdev->rs_mark_left =drbd_bm_total_weight(mdev);
			}
		}
		drbd_try_clear_on_disk_bm(mdev,sector,count);
		/* just wake_up unconditional now,
		 * various lc_chaged(), lc_put() in drbd_try_clear_on_disk_bm(). */
		wake_up=1;
	}
	spin_unlock_irq(&mdev->al_lock);
	if(wake_up) wake_up(&mdev->al_wait);
}

/*
 * this is intended to set one request worth of data out of sync.
 * affects at least 1 bit, and at most 1+PAGE_SIZE/BM_BLOCK_SIZE bits.
 *
 * called by tl_clear and drbd_send_dblock (==drbd_make_request).
 * so this can be _any_ process.
 */
void __drbd_set_out_of_sync(drbd_dev* mdev, sector_t sector, int size, const char* file, const unsigned int line)
{
	unsigned long sbnr,ebnr,lbnr,bnr;
	sector_t esector, nr_sectors;
	int strange_state;

	strange_state = ( mdev->cstate  > Connected ) ||
	                ( mdev->cstate == Connected &&
	                 !(test_bit(DISKLESS,&mdev->flags) ||
	                   test_bit(PARTNER_DISKLESS,&mdev->flags)) );
	if (strange_state) {
		ERR("%s:%d: %s flags=0x%02lx\n", file , line ,
				cstate_to_name(mdev->cstate), mdev->flags);
	}

	if (size <= 0 || (size & 0x1ff) != 0 || size > PAGE_SIZE) {
		ERR("sector: %lu, size: %d\n",(unsigned long)sector,size);
		return;
	}

	nr_sectors = drbd_get_capacity(mdev->this_bdev);
	esector = sector + (size>>9) -1;

	ERR_IF(sector >= nr_sectors) return;
	ERR_IF(esector >= nr_sectors) esector = (nr_sectors-1);

	lbnr = BM_SECT_TO_BIT(nr_sectors-1);

	/* we set it out of sync,
	 * we do not need to round anything here */
	sbnr = BM_SECT_TO_BIT(sector);
	ebnr = BM_SECT_TO_BIT(esector);

	/*
	 * ok, (capacity & 7) != 0 sometimes, but who cares...
	 * we count rs_{total,left} in bits, not sectors.
	 */
	for(bnr=sbnr; bnr <= ebnr; bnr++) drbd_bm_set_bit(mdev,bnr);
}

static inline
struct bm_extent* _bme_get(struct Drbd_Conf *mdev, unsigned int enr)
{
	struct bm_extent  *bm_ext;
	int wakeup = 0;
	unsigned long     rs_flags;

	if(atomic_read(&mdev->resync_locked) > mdev->resync->nr_elements-3 ) {
		//WARN("bme_get() does not lock all elements\n");
		return 0;
	}

	spin_lock_irq(&mdev->al_lock);
	bm_ext = (struct bm_extent*) lc_get(mdev->resync,enr);
	if (bm_ext) {
		if(bm_ext->lce.lc_number != enr) {
			bm_ext->rs_left = drbd_bm_e_weight(mdev,enr);
			lc_changed(mdev->resync,(struct lc_element*)bm_ext);
			wakeup = 1;
		}
		if(bm_ext->lce.refcnt == 1) atomic_inc(&mdev->resync_locked);
		set_bit(BME_NO_WRITES,&bm_ext->flags); // within the lock
	}
	rs_flags=mdev->resync->flags;
	spin_unlock_irq(&mdev->al_lock);
	if (wakeup) wake_up(&mdev->al_wait);

	if(!bm_ext) {
		if (rs_flags & LC_STARVING) {
			WARN("Have to wait for element"
			     " (resync LRU too small?)\n");
		}
		if (rs_flags & LC_DIRTY) {
			BUG(); // WARN("Ongoing RS update (???)\n");
		}
	}

	return bm_ext;
}

static inline int _is_in_al(drbd_dev* mdev, unsigned int enr)
{
	struct lc_element* al_ext;
	int rv=0;

	spin_lock_irq(&mdev->al_lock);
	if(unlikely(enr == mdev->act_log->new_number)) rv=1;
	else {
		al_ext = lc_find(mdev->act_log,enr);
		if(al_ext) {
			if (al_ext->refcnt) rv=1;
		}
	}
	spin_unlock_irq(&mdev->al_lock);

	/*
	if(unlikely(rv)) {
		INFO("Delaying sync read until app's write is done\n");
	}
	*/
	return rv;
}

/**
 * drbd_rs_begin_io: Gets an extent in the resync LRU cache and sets it
 * to BME_LOCKED.
 *
 * @sector: The sector number
 */
int drbd_rs_begin_io(drbd_dev* mdev, sector_t sector)
{
	unsigned int enr = BM_SECT_TO_EXT(sector);
	struct bm_extent* bm_ext;
	int i, sig;

	sig = wait_event_interruptible( mdev->al_wait,
			(bm_ext = _bme_get(mdev,enr)) );
	if (sig) return 0;

	if(test_bit(BME_LOCKED,&bm_ext->flags)) return 1;

	for(i=0;i<AL_EXT_PER_BM_SECT;i++) {
		sig = wait_event_interruptible( mdev->al_wait,
				!_is_in_al(mdev,enr*AL_EXT_PER_BM_SECT+i) );
		if (sig) {
			spin_lock_irq(&mdev->al_lock);
			if( lc_put(mdev->resync,&bm_ext->lce) == 0 ) {
				clear_bit(BME_NO_WRITES,&bm_ext->flags);
				atomic_dec(&mdev->resync_locked);
				wake_up(&mdev->al_wait);
			}
			spin_unlock_irq(&mdev->al_lock);
			return 0;
		}
	}

	set_bit(BME_LOCKED,&bm_ext->flags);

	return 1;
}

void drbd_rs_complete_io(drbd_dev* mdev, sector_t sector)
{
	unsigned int enr = BM_SECT_TO_EXT(sector);
	struct bm_extent* bm_ext;
	unsigned long flags;

	spin_lock_irqsave(&mdev->al_lock,flags);
	bm_ext = (struct bm_extent*) lc_find(mdev->resync,enr);
	if(!bm_ext) {
		spin_unlock_irqrestore(&mdev->al_lock,flags);
		ERR("drbd_rs_complete_io() called, but extent not found\n");
		return;
	}

	if( lc_put(mdev->resync,(struct lc_element *)bm_ext) == 0 ) {
		clear_bit(BME_LOCKED,&bm_ext->flags);
		clear_bit(BME_NO_WRITES,&bm_ext->flags);
		atomic_dec(&mdev->resync_locked);
		wake_up(&mdev->al_wait);
	}

	spin_unlock_irqrestore(&mdev->al_lock,flags);
}

/**
 * drbd_rs_cancel_all: Removes extents from the resync LRU. Even
 * if they are BME_LOCKED.
 */
void drbd_rs_cancel_all(drbd_dev* mdev)
{
	struct bm_extent* bm_ext;
	int i;

	spin_lock_irq(&mdev->al_lock);

	for(i=0;i<mdev->resync->nr_elements;i++) {
		bm_ext = (struct bm_extent*) lc_entry(mdev->resync,i);
		if(bm_ext->lce.lc_number == LC_FREE) continue;
		bm_ext->lce.refcnt = 0; // Rude but ok.
		bm_ext->rs_left = 0;
		clear_bit(BME_LOCKED,&bm_ext->flags);
		clear_bit(BME_NO_WRITES,&bm_ext->flags);
		lc_del(mdev->resync,&bm_ext->lce);
	}
	atomic_set(&mdev->resync_locked,0);   
	spin_unlock_irq(&mdev->al_lock);
	wake_up(&mdev->al_wait);
}
