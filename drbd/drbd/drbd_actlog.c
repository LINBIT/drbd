/*
-*- linux-c -*-
   drbd_actlog.c
   Kernel module for 2.2.x/2.4.x Kernels

   This file is part of drbd by Philipp Reisner.

   Copyright (C) 2003, Philipp Reisner <philipp.reisner@gmx.at>.
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

#include <linux/slab.h>
#include <linux/drbd.h>
#include "drbd_int.h"

#define AL_EXTENTS_PT 61

/* This is what I like so much about the linux kernel:
 * if you have a close look, you can almost always reuse code by someone else
 * ;)
 * this is mostly from drivers/md/md.c
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
int drbd_md_sync_page_io(drbd_dev *mdev, sector_t sector, int rw)
{
	struct buffer_head bh;
	struct completion event;

	if (!mdev->md_bdev) {
		if (DRBD_ratelimit(5*HZ,5)) {
			ERR("mdev->md_bdev==NULL\n");
			dump_stack();
		}
		return 0;
	}
#ifdef PARANOIA
	if (rw != WRITE) {
		void *b = page_address(mdev->md_io_page);
		memset(b,0,PAGE_SIZE);
	}
#endif
	init_completion(&event);
	init_buffer(&bh, drbd_md_io_complete, &event);
	bh.b_rdev = mdev->md_bdev;
	bh.b_rsector = sector;
	bh.b_state = (1 << BH_Req) | (1 << BH_Mapped) | (1 << BH_Lock);
	bh.b_size = 512; // THINK: always? well, we can add an other parameter
	bh.b_page = mdev->md_io_page;
	bh.b_reqnext = NULL;
	bh.b_data = page_address(mdev->md_io_page);
	generic_make_request(rw, &bh);

	run_task_queue(&tq_disk);
	wait_for_completion(&event);

	return test_bit(BH_Uptodate, &bh.b_state);
}
#else
int drbd_md_sync_page_io(drbd_dev *mdev, sector_t sector, int rw)
{
	struct bio bio;
	struct bio_vec vec;
	struct completion event;

	if (!mdev->md_bdev) {
		if (DRBD_ratelimit(5*HZ,5)) {
			ERR("mdev->md_bdev==NULL\n");
			dump_stack();
		}
		return 0;
	}
#ifdef PARANOIA
	if (rw != WRITE) {
		void *b = page_address(mdev->md_io_page);
		memset(b,0,PAGE_SIZE);
	}
#endif
	bio_init(&bio);
	bio.bi_io_vec = &vec;
	vec.bv_page = mdev->md_io_page;
	vec.bv_offset = 0;
	vec.bv_len =
	bio.bi_size = 512; // THINK: always? well, we can add an other parameter
	bio.bi_vcnt = 1;
	bio.bi_idx = 0;
	bio.bi_bdev = mdev->md_bdev;
	bio.bi_sector = sector;
	init_completion(&event);
	bio.bi_private = &event;
	bio.bi_end_io = drbd_md_io_complete;

	/*
	INFO("%s [%d]:%s(,%ld,%s)\n",
	     current->comm, current->pid, __func__,
	     sector, rw ? "WRITE" : "READ");
	*/
#ifdef BIO_RW_SYNC
	submit_bio(rw | (1 << BIO_RW_SYNC), &bio);
#else
	submit_bio(rw, &bio);
	drbd_blk_run_queue(bdev_get_queue(mdev->md_bdev));
#endif
	wait_for_completion(&event);

	return test_bit(BIO_UPTODATE, &bio.bi_flags);
}
#endif

struct al_transaction {
	u32       magic;
	u32       tr_number;
	// u32       tr_generation; //TODO
	struct {
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

STATIC void drbd_al_write_transaction(struct Drbd_Conf *,struct lc_element *,
				      unsigned int );
STATIC void drbd_update_on_disk_bm(struct Drbd_Conf *,unsigned int);

#define SM (BM_EXTENT_SIZE / AL_EXTENT_SIZE)

static inline
struct lc_element* _al_get(struct Drbd_Conf *mdev, unsigned int enr)
{
	struct lc_element *al_ext;
	struct bm_extent  *bm_ext;
	unsigned long     al_flags=0;

	spin_lock_irq(&mdev->al_lock);
	bm_ext = (struct bm_extent*) lc_find(mdev->resync,enr/SM);
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

	D_ASSERT(atomic_read(&mdev->local_cnt)>0);
	wait_event(mdev->al_wait, (al_ext = _al_get(mdev,enr)) );

	if (al_ext->lc_number != enr) {
		// We have to do write an transaction to AL.
		unsigned int evicted;

		evicted = al_ext->lc_number;

		if(mdev->cstate < Connected && evicted != LC_FREE ) {
			drbd_update_on_disk_bm(mdev,evicted);
		}
		drbd_al_write_transaction(mdev,al_ext,enr);
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

STATIC void
drbd_al_write_transaction(struct Drbd_Conf *mdev,struct lc_element *updated,
			  unsigned int new_enr)
{
	int i,n,mx;
	unsigned int extent_nr;
	struct al_transaction* buffer;
	sector_t sector;
	u32 xor_sum=0;

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
	mdev->al_tr_number++;

	up(&mdev->md_io_mutex);
}

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
		return 0;
	}

	rv = ( be32_to_cpu(b->magic) == DRBD_MAGIC );

	for(i=0;i<AL_EXTENTS_PT+1;i++) {
		xor_sum ^= be32_to_cpu(b->updates[i].extent);
	}
	rv &= (xor_sum == be32_to_cpu(b->xor_sum));

	return rv;
}

void drbd_al_read_log(struct Drbd_Conf *mdev)
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
		if(!drbd_al_read_tr(mdev,buffer,i)) continue;
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
		return;
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
		ERR_IF(!rv) goto cancel;

		trn=be32_to_cpu(buffer->tr_number);

		spin_lock_irq(&mdev->al_lock);
		for(j=0;j<AL_EXTENTS_PT+1;j++) {
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
}

/**
 * drbd_al_to_on_disk_bm: Writes the areas of the bitmap which are covered by
 * the AL.
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
		drbd_update_on_disk_bm(mdev,enr);
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
	int i;
	unsigned int enr;
	unsigned long add=0;

	wait_event(mdev->al_wait, lc_try_lock(mdev->act_log));

	for(i=0;i<mdev->act_log->nr_elements;i++) {
		enr = lc_entry(mdev->act_log,i)->lc_number;
		if(enr == LC_FREE) continue;
		add += bm_set_bit( mdev, enr << (AL_EXTENT_SIZE_B-9),
				   AL_EXTENT_SIZE, SS_OUT_OF_SYNC );
	}

	lc_unlock(mdev->act_log);
	wake_up(&mdev->al_wait);

	INFO("Marked additional %lu KB as out-of-sync based on AL.\n",(add+1)/2);

	mdev->rs_total += add;
}

/**
 * drbd_write_bm: Writes the whole bitmap to its on disk location.
 */
void drbd_write_bm(struct Drbd_Conf *mdev)
{
	unsigned int exts,i;

	if( !inc_local_md_only(mdev) ) return;

	exts = div_ceil(drbd_get_capacity(mdev->this_bdev),
			BM_EXTENT_SIZE >> 9 );

	for(i=0;i<exts;i++) {
		drbd_update_on_disk_bm(mdev,i*EXTENTS_PER_SECTOR);
	}
	dec_local(mdev);
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

/**
 * drbd_read_bm: Read the whole bitmap from its on disk location.
 */
void drbd_read_bm(struct Drbd_Conf *mdev)
{
	unsigned long * buffer, * bm, word;
	sector_t sector;
	int want,bm_words,bm_i,buf_i;
	unsigned long bits=0;
	int so = 0;

	bm_i = 0;
	bm_words = mdev->mbds_id->size/sizeof(long);
	bm = mdev->mbds_id->bm;

	down(&mdev->md_io_mutex);
	buffer = (unsigned long *)page_address(mdev->md_io_page);

	while (1) {
		want=min_t(int,512/sizeof(long),bm_words-bm_i);
		if(want == 0) break;

		sector = drbd_md_ss(mdev) + MD_BM_OFFSET + so;
		so++;

		if(!drbd_md_sync_page_io(mdev,sector,READ)) {
			drbd_chk_io_error(mdev, 1);
			drbd_io_error(mdev);
			break;
			//return 0; // FIXME error propagation...
		}

		for(buf_i=0;buf_i<want;buf_i++) {
			word = lel_to_cpu(buffer[buf_i]);
			bits += hweight_long(word);
			bm[bm_i++] = word;
		}
	}

	up(&mdev->md_io_mutex);

	mdev->rs_total = (bits << (BM_BLOCK_SIZE_B - 9)) +
		bm_end_of_dev_case(mdev->mbds_id);

	INFO("%lu KB marked out-of-sync by on disk bit-map.\n",
	     (unsigned long) (mdev->rs_total+1)>>1);
}

/**
 * drbd_update_on_disk_bm: Writes a piece of the bitmap to its
 * on disk location.
 *
 * @enr: The extent number of the bits we should write to disk.
 *       ATTENTION: Based on AL_EXTENT_SIZE, although the chunk
 *                  we write might represent more storage. 
 *                  ( actually AL_EXTENT_SIZE*EXTENTS_PER_SECTOR )
 */
STATIC void drbd_update_on_disk_bm(struct Drbd_Conf *mdev,unsigned int enr)
{
	unsigned long * buffer, * bm;
	unsigned int want,buf_i,bm_words,bm_i;
	sector_t sector;

	D_ASSERT(atomic_read(&mdev->local_cnt)>0);
	enr = (enr & ~(EXTENTS_PER_SECTOR-1) );

	bm = mdev->mbds_id->bm;
	bm_words = mdev->mbds_id->size/sizeof(long);
	bm_i = enr * BM_WORDS_PER_EXTENT ;

	if(bm_i >= bm_words) {
		if (DRBD_ratelimit(5*HZ,5)) {
			ERR("%s:%d:%s: (bm_i=%u) >= (bm_words=%u)",
			    __FILE__, __LINE__, __FUNCTION__,
			    bm_i, bm_words);
			dump_stack();
		}
		return;
	}
	want=min_t(unsigned int,512/sizeof(long),bm_words-bm_i);

	down(&mdev->md_io_mutex); // protects md_io_buffer
	buffer = (unsigned long *)page_address(mdev->md_io_page);

	for(buf_i=0;buf_i<want;buf_i++) {
		buffer[buf_i] = cpu_to_lel(bm[bm_i++]);
	}

	sector = drbd_md_ss(mdev) + MD_BM_OFFSET + enr/EXTENTS_PER_SECTOR;

	if(!drbd_md_sync_page_io(mdev,sector,WRITE)) {
		drbd_chk_io_error(mdev, 1);
		drbd_io_error(mdev);
	}
	up(&mdev->md_io_mutex);

	mdev->bm_writ_cnt++;
}

STATIC int w_update_odbm(drbd_dev *mdev, struct drbd_work *w, int unused)
{
	struct update_odbm_work *udw = (struct update_odbm_work*)w;

	if( !inc_local_md_only(mdev) ) {
		if (DRBD_ratelimit(5*HZ,5))
			WARN("Can not update on disk bitmap, local IO disabled.\n");
		return 1;
	}

	drbd_update_on_disk_bm(mdev,udw->enr);
	dec_local(mdev);

	kfree(udw);

	if(mdev->rs_left == 0 && 
	   ( mdev->cstate == SyncSource || mdev->cstate == SyncTarget ) ) {
		D_ASSERT( mdev->resync_work.cb == w_resync_inactive );
		drbd_resync_finished(mdev);
	}

	return 1;
}


/* ATTENTION. The AL's extents are 4MB each, while the extents in the  *
 * resync LRU-cache are 16MB each.                                     */
STATIC void drbd_try_clear_on_disk_bm(struct Drbd_Conf *mdev,sector_t sector,
				      int cleared)
{
	struct list_head *le, *tmp;
	struct bm_extent* ext;
	struct update_odbm_work * udw;

	unsigned int enr;
	unsigned long flags;

	// I simply assume that a sector/size pair never crosses
	// a 16 MB extent border. (Currently this is true...)
	enr = (sector >> (BM_EXTENT_SIZE_B-9));

	spin_lock_irqsave(&mdev->al_lock,flags);
	ext = (struct bm_extent *) lc_get(mdev->resync,enr);
	if (ext) {
		if( ext->lce.lc_number == enr) {
			ext->rs_left -= cleared;
			D_ASSERT(ext->rs_left >= 0);
		} else {
			//WARN("Recounting sectors in %d (resync LRU too small?)\n", enr);
			// This element should be in the cache
			// since drbd_rs_begin_io() pulled it already in.
			ext->rs_left = bm_count_sectors(mdev->mbds_id,enr);
			lc_changed(mdev->resync,&ext->lce);
		}
		lc_put(mdev->resync,&ext->lce);
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
			udw->enr = enr*SM;
			udw->w.cb = w_update_odbm;
			drbd_queue_work_front(mdev,&mdev->data.work,&udw->w);
			lc_del(mdev->resync,&ext->lce);
		}
	}

	spin_unlock_irqrestore(&mdev->al_lock,flags);
	// just wake_up unconditional now. [various lc_chaged(), lc_put() here]
	wake_up(&mdev->al_wait);
}

void drbd_set_in_sync(drbd_dev* mdev, sector_t sector, int blk_size)
{
	/* Is called by drbd_dio_end possibly from IRQ context, but
	   from other places in non IRQ */
	unsigned long flags=0;
	int cleared;

	cleared = bm_set_bit(mdev, sector, blk_size, SS_IN_SYNC);

	if( cleared == 0 ) return;

	spin_lock_irqsave(&mdev->al_lock,flags);
	mdev->rs_left -= cleared;
	D_ASSERT((long)mdev->rs_left >= 0);

	if(jiffies - mdev->rs_mark_time > HZ*10) {
		mdev->rs_mark_time=jiffies;
		mdev->rs_mark_left=mdev->rs_left;
	}
	spin_unlock_irqrestore(&mdev->al_lock,flags);

	drbd_try_clear_on_disk_bm(mdev,sector,cleared);
}


static inline
struct bm_extent* _bme_get(struct Drbd_Conf *mdev, unsigned int enr)
{
	struct bm_extent  *bm_ext;
	unsigned long     rs_flags;

	if(atomic_read(&mdev->resync_locked) > mdev->resync->nr_elements-3 ) {
		//WARN("bme_get() does not lock all elements\n");
		return 0;
	}

	spin_lock_irq(&mdev->al_lock);
	bm_ext = (struct bm_extent*) lc_get(mdev->resync,enr);
	if (bm_ext) {
		if(bm_ext->lce.lc_number != enr) {
			bm_ext->rs_left = bm_count_sectors(mdev->mbds_id,enr);
			lc_changed(mdev->resync,(struct lc_element*)bm_ext);
			wake_up(&mdev->al_wait);
		}
		if(bm_ext->lce.refcnt == 1) atomic_inc(&mdev->resync_locked);
		set_bit(BME_NO_WRITES,&bm_ext->flags); // within the lock
	}
	rs_flags=mdev->resync->flags;
	spin_unlock_irq(&mdev->al_lock);

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
	unsigned int enr = (sector >> (BM_EXTENT_SIZE_B-9));
	struct bm_extent* bm_ext;
	int i;

	if( wait_event_interruptible(mdev->al_wait, 
				     (bm_ext = _bme_get(mdev,enr)) ) ) {
		return 0;
	}

	if(test_bit(BME_LOCKED,&bm_ext->flags)) return 1;

	for(i=0;i<SM;i++) {
		if( wait_event_interruptible(mdev->al_wait, 
					     !_is_in_al(mdev,enr*SM+i) ) ) {
			if( lc_put(mdev->resync,&bm_ext->lce) == 0 ) {
				clear_bit(BME_NO_WRITES,&bm_ext->flags);
				atomic_dec(&mdev->resync_locked);
				wake_up(&mdev->al_wait);
				return 0;
			}
		}
	}

	set_bit(BME_LOCKED,&bm_ext->flags);

	return 1;
}

void drbd_rs_complete_io(drbd_dev* mdev, sector_t sector)
{
	unsigned int enr = (sector >> (BM_EXTENT_SIZE_B-9));
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
	spin_unlock_irq(&mdev->al_lock);
	wake_up(&mdev->al_wait);
}
