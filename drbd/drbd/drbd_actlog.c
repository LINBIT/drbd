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
#include "drbd.h"
#include "drbd_int.h"

#define AL_EXTENT_SIZE_B 22             // One extent represents 4M Storage
#define AL_EXTENT_SIZE (1<<AL_EXTENT_SIZE_B)
#define AL_EXTENTS_PT 61

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

STATIC void drbd_al_write_transaction(struct Drbd_Conf *,struct lc_element *);
STATIC void drbd_update_on_disk_bm(struct Drbd_Conf *,unsigned int ,int);

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
			WARN("Delaying app write until sync read is done\n");
			return 0;
		}
	}
	al_ext   = lc_get(mdev->act_log,enr);
	al_flags = mdev->act_log->flags;
	spin_unlock_irq(&mdev->al_lock);

	if (!al_ext) {
		if (al_flags & LC_STARVING)
			WARN("Have to wait for LRU element (AL too small?)\n");
		if (al_flags & LC_DIRTY)
			WARN("Ongoing AL update (AL device too slow?)\n");
	}

	return al_ext;
}

void drbd_al_begin_io(struct Drbd_Conf *mdev, sector_t sector)
{
	unsigned int enr = (sector >> (AL_EXTENT_SIZE_B-9));
	struct lc_element *al_ext;

	wait_event(mdev->al_wait, (al_ext = _al_get(mdev,enr)) );

	if (al_ext->lc_number != enr) {
		// We have to do write an transaction to AL.
		unsigned long evicted;

		evicted = al_ext->lc_number;
		al_ext->lc_number = enr;

		if(mdev->cstate < Connected && evicted != LC_FREE ) {
			drbd_update_on_disk_bm(mdev,evicted,1);
		}
		drbd_al_write_transaction(mdev,al_ext);
		mdev->al_writ_cnt++;

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
		ERR("drbd_al_complete_io() called on inactive extent\n");
		return;
	}

	if( lc_put(mdev->act_log,extent) == 0 ) {
		wake_up(&mdev->al_wait);
	}

	spin_unlock_irqrestore(&mdev->al_lock,flags);
}

STATIC void
drbd_al_write_transaction(struct Drbd_Conf *mdev,struct lc_element *updated)
{
	int i,n,mx;
	unsigned int extent_nr;
	struct al_transaction* buffer;
	sector_t sector;
	u32 xor_sum=0;

	down(&mdev->md_io_mutex); // protects md_io_buffer, al_tr_cycle, ...
	buffer = (struct al_transaction*)bh_kmap(&mdev->md_io_bh);

	buffer->magic = __constant_cpu_to_be32(DRBD_MAGIC);
	buffer->tr_number = cpu_to_be32(mdev->al_tr_number);

	n = lc_index_of(mdev->act_log, updated);

	buffer->updates[0].pos = cpu_to_be32(n);
	buffer->updates[0].extent = cpu_to_be32(updated->lc_number);

#if 0	/* Use this printf with the test_al.pl program */
	ERR("T%03d S%03d=E%06d\n", mdev->al_tr_number,n,updated->lc_number);
#endif

	xor_sum ^= updated->lc_number;

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

	bh_kunmap(&mdev->md_io_bh);

	sector = drbd_md_ss(mdev) + MD_AL_OFFSET + mdev->al_tr_pos ;

	drbd_set_md_bh(mdev, &mdev->md_io_bh, sector, 512);
	set_bit(BH_Dirty, &mdev->md_io_bh.b_state);
	set_bit(BH_Lock, &mdev->md_io_bh.b_state);
	mdev->md_io_bh.b_end_io = drbd_generic_end_io;
	generic_make_request(WRITE,&mdev->md_io_bh);
	wait_on_buffer(&mdev->md_io_bh);

	if( ++mdev->al_tr_pos > div_ceil(mdev->act_log->nr_elements,AL_EXTENTS_PT) ) {
		mdev->al_tr_pos=0;
	}
	mdev->al_tr_number++;

	up(&mdev->md_io_mutex);
}

/* In case this function returns 1 == success, the caller must do
		bh_kunmap(&mdev->md_io_bh);
		up(&mdev->md_io_mutex);
 */
STATIC int drbd_al_read_tr(struct Drbd_Conf *mdev,
			   struct al_transaction** bp,
			   int index)
{
	struct al_transaction* buffer;
	sector_t sector;
	int rv,i;
	u32 xor_sum=0;

	down(&mdev->md_io_mutex);
	sector = drbd_md_ss(mdev) + MD_AL_OFFSET + index;

	drbd_set_md_bh(mdev, &mdev->md_io_bh, sector, 512);
	clear_bit(BH_Uptodate, &mdev->md_io_bh.b_state);
	set_bit(BH_Lock, &mdev->md_io_bh.b_state);
	mdev->md_io_bh.b_end_io = drbd_generic_end_io;
	generic_make_request(READ,&mdev->md_io_bh);
	wait_on_buffer(&mdev->md_io_bh);

	buffer = (struct al_transaction*)bh_kmap(&mdev->md_io_bh);

	rv = ( be32_to_cpu(buffer->magic) == DRBD_MAGIC );

	for(i=0;i<AL_EXTENTS_PT+1;i++) {
		xor_sum ^= be32_to_cpu(buffer->updates[i].extent);
	}
	rv &= (xor_sum == be32_to_cpu(buffer->xor_sum));

	if(rv) {
		*bp = buffer;
	} else {
		bh_kunmap(&mdev->md_io_bh);
		up(&mdev->md_io_mutex);
	}

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

	// Find the valid transaction in the log
	for(i=0;i<=mx;i++) {
		if(!drbd_al_read_tr(mdev,&buffer,i)) continue;
		cnr = be32_to_cpu(buffer->tr_number);
		// INFO("index %d valid tnr=%d\n",i,cnr);
		bh_kunmap(&mdev->md_io_bh);
		up(&mdev->md_io_mutex);

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
		//TODO set all bits in the bitmap!
		return;
	}

	// Read the valid transactions.
	// INFO("Reading from %d to %d.\n",from,to);

	i=from;
	while(1) {
		int j,pos;
		unsigned int extent_nr;
		unsigned int trn;

		rv = drbd_al_read_tr(mdev,&buffer,i);
		ERR_IF(!rv) goto cancel;

		trn=be32_to_cpu(buffer->tr_number);

		for(j=0;j<AL_EXTENTS_PT+1;j++) {
			pos = be32_to_cpu(buffer->updates[j].pos);
			extent_nr = be32_to_cpu(buffer->updates[j].extent);

			if(extent_nr == LC_FREE) continue;

		       //if(j<3) INFO("T%03d S%03d=E%06d\n",trn,pos,extent_nr);
			spin_lock_irq(&mdev->al_lock);
			lc_set(mdev->act_log,extent_nr,pos);
			spin_unlock_irq(&mdev->al_lock);
			active_extents++;
		}

		bh_kunmap(&mdev->md_io_bh);
		up(&mdev->md_io_mutex);

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

	for(i=0;i<mdev->act_log->nr_elements;i++) {
		enr = lc_entry(mdev->act_log,i)->lc_number;
		if(enr == LC_FREE) continue;
		drbd_update_on_disk_bm(mdev,enr,1);
	}

	lc_unlock(mdev->act_log);
	wake_up(&mdev->al_wait);
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

	INFO("Marked additional %lu KB as out-of-sync based on AL.\n",add/2);

	mdev->rs_total += add;
}

/**
 * drbd_write_bm: Writes the whole bitmap to its on disk location.
 */
void drbd_write_bm(struct Drbd_Conf *mdev)
{
	unsigned int exts,i;
	exts = div_ceil(mdev->mbds_id->size,BM_EXTENT_SIZE);

	for(i=0;i<exts;i++) {
		drbd_update_on_disk_bm(mdev,i,1);
	}
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
	bm_words = mdev->mbds_id->size/sizeof(unsigned long);
	bm = mdev->mbds_id->bm;

	down(&mdev->md_io_mutex);

	while (1) {
		want=min_t(int,512/sizeof(long),bm_words-bm_i);
		if(want == 0) break;

		sector = drbd_md_ss(mdev) + MD_BM_OFFSET + so;
		so++;

		drbd_set_md_bh(mdev, &mdev->md_io_bh, sector, 512);
		clear_bit(BH_Uptodate, &mdev->md_io_bh.b_state);
		set_bit(BH_Lock, &mdev->md_io_bh.b_state);
		mdev->md_io_bh.b_end_io = drbd_generic_end_io;
		generic_make_request(READ,&mdev->md_io_bh);
		wait_on_buffer(&mdev->md_io_bh);

		buffer = (unsigned long *)bh_kmap(&mdev->md_io_bh);

		for(buf_i=0;buf_i<want;buf_i++) {
			word = lel_to_cpu(buffer[buf_i]);
			bits += hweight_long(word);
			bm[bm_i++] = word;
		}
		bh_kunmap(&mdev->md_io_bh);
	}

	up(&mdev->md_io_mutex);

	mdev->rs_total = (bits << (BM_BLOCK_SIZE_B - 9)) +
		bm_end_of_dev_case(mdev->mbds_id);

	INFO("%lu KB marked out-of-sync by on disk bit-map.\n",
	     mdev->rs_total/2);
}

STATIC void drbd_async_eio(struct buffer_head *bh, int uptodate)
{
	struct Drbd_Conf *mdev;

	mdev = container_of(bh,struct Drbd_Conf,md_io_bh);
	PARANOIA_BUG_ON(!IS_VALID_MDEV(mdev));

	mark_buffer_uptodate(bh, uptodate);
	unlock_buffer(bh);
	up(&mdev->md_io_mutex);
}


#define BM_WORDS_PER_EXTENT ( (AL_EXTENT_SIZE/BM_BLOCK_SIZE) / BITS_PER_LONG )
#define BM_BYTES_PER_EXTENT ( (AL_EXTENT_SIZE/BM_BLOCK_SIZE) / 8 )
#define EXTENTS_PER_SECTOR  ( 512 / BM_BYTES_PER_EXTENT )
/**
 * drbd_update_on_disk_bm: Writes a piece of the bitmap to its
 * on disk location.
 *
 * @enr: The extent number of the bits we should write to disk.
 */
STATIC void drbd_update_on_disk_bm(struct Drbd_Conf *mdev,unsigned int enr,
				       int sync)
{
	unsigned long * buffer, * bm;
	int want,buf_i,bm_words,bm_i;
	sector_t sector;

	enr = (enr & ~(EXTENTS_PER_SECTOR-1) );

	bm = mdev->mbds_id->bm;
	bm_words = mdev->mbds_id->size/sizeof(unsigned long);
	bm_i = enr * BM_WORDS_PER_EXTENT ;
	want=min_t(int,512/sizeof(long),bm_words-bm_i);

	down(&mdev->md_io_mutex); // protects md_io_buffer
	buffer = (unsigned long *)bh_kmap(&mdev->md_io_bh);

	for(buf_i=0;buf_i<want;buf_i++) {
		buffer[buf_i] = cpu_to_lel(bm[bm_i++]);
	}

	bh_kunmap(&mdev->md_io_bh);

	sector = drbd_md_ss(mdev) + MD_BM_OFFSET + enr/EXTENTS_PER_SECTOR;

	drbd_set_md_bh(mdev, &mdev->md_io_bh, sector, 512);
	set_bit(BH_Dirty, &mdev->md_io_bh.b_state);
	set_bit(BH_Lock, &mdev->md_io_bh.b_state);
	mdev->md_io_bh.b_end_io = sync ? drbd_generic_end_io : drbd_async_eio;
	generic_make_request(WRITE,&mdev->md_io_bh);
	if(sync) {
		wait_on_buffer(&mdev->md_io_bh);
		up(&mdev->md_io_mutex);
	}

	mdev->bm_writ_cnt++;
}
#undef BM_WORDS_PER_EXTENT
#undef EXTENTS_PER_SECTOR

/* ATTENTION. The AL's extents are 4MB each, while the extents in the  *
 * resync LRU-cache are 16MB each.                                     */
STATIC void drbd_try_clear_on_disk_bm(struct Drbd_Conf *mdev,sector_t sector,
				      int cleared,int may_sleep)
{
	struct bm_extent* ext;
	unsigned long enr;
	unsigned long flags;

	// I simply assume that a sector/size pair never crosses
	// a 16 MB extent border. (Currently this is true...)
	enr = (sector >> (BM_EXTENT_SIZE_B-9));

	spin_lock_irqsave(&mdev->al_lock,flags);
	ext = (struct bm_extent *) lc_get(mdev->resync,enr);
	if (ext) {
		if( ext->lce.lc_number == enr) {
			ext->rs_left -= cleared;
			D_ASSERT((long)ext->rs_left >= 0);
		} else {
			if(mdev->cstate == SyncSource) {
				WARN("Recounting sectors"
				     " (resync LRU too small?)\n");
				// On the SyncSource the element should be
				// in the cache since drbd_rs_begin_io()
				// pulled it already in.
			}
			ext->rs_left = bm_count_sectors(mdev->mbds_id,enr);
			lc_changed(mdev->resync,(struct lc_element*)ext);
		}
		lc_put(mdev->resync,(struct lc_element*)ext);
	} else {
		ERR("lc_get() failed! Probabely something stays"
		    " dirty in the on disk BM\n");
	}
	spin_unlock_irqrestore(&mdev->al_lock,flags);

	if(may_sleep) {
		struct list_head *le;

		spin_lock(&mdev->al_lock);
	restart:
		list_for_each(le,&mdev->resync->lru) {
			ext=(struct bm_extent *)list_entry(le,struct lc_element,list);
			if(ext->rs_left == 0) {
				spin_unlock(&mdev->al_lock);
				drbd_update_on_disk_bm(mdev,enr*SM,1);
				// TODO: reconsider to use the async version
				// of drbd_update_on_disk_bm()
				//INFO("Clearing e# %lu of on disk bm\n",enr);
				spin_lock(&mdev->al_lock);
				lc_del(mdev->resync,&ext->lce);
				goto restart;
			}
		}
		spin_unlock(&mdev->al_lock);
	}
}

void drbd_set_in_sync(drbd_dev* mdev, sector_t sector,
		      int blk_size, int may_sleep)
{
	/* Is called by drbd_dio_end possibly from IRQ context, but
	   from other places in non IRQ */
	unsigned long flags=0;
	int cleared;
	int finished=0;

	cleared = bm_set_bit(mdev, sector, blk_size, SS_IN_SYNC);

	spin_lock_irqsave(&mdev->al_lock,flags);
	mdev->rs_left -= cleared;
	D_ASSERT((long)mdev->rs_left >= 0);
	if( cleared && mdev->rs_left == 0 ) finished=1;

	if(jiffies - mdev->rs_mark_time > HZ*10) {
		mdev->rs_mark_time=jiffies;
		mdev->rs_mark_left=mdev->rs_left;
	}
	spin_unlock_irqrestore(&mdev->al_lock,flags);

	drbd_try_clear_on_disk_bm(mdev,sector,cleared,may_sleep);

	if( finished ) {
		// This must be after the last call to clear_on_disk_bm() !
		D_ASSERT( mdev->resync_work.cb == w_resync_inactive );
		mdev->resync_work.cb = w_resync_finished;
		__drbd_queue_work(mdev,&mdev->data.work,&mdev->resync_work);
	}
}


static inline
struct bm_extent* _bme_get(struct Drbd_Conf *mdev, unsigned int enr)
{
	struct bm_extent  *bm_ext;
	unsigned long     rs_flags;

	spin_lock_irq(&mdev->al_lock);
	bm_ext = (struct bm_extent*) lc_get(mdev->resync,enr);
	if (bm_ext) {
		if(bm_ext->lce.lc_number != enr) {
			bm_ext->rs_left = bm_count_sectors(mdev->mbds_id,enr);
			lc_changed(mdev->resync,(struct lc_element*)bm_ext);
			wake_up(&mdev->al_wait);
		}
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

	if(rv) WARN("Delaying sync read until app's write is done\n");

	return rv;
}

/**
 * drbd_rs_begin_io: Gets an extent in the resync LRU cache and sets it
 * to BME_LOCKED.
 *
 * @sector: The sector number
 */
void drbd_rs_begin_io(drbd_dev* mdev, sector_t sector)
{
	unsigned int enr = (sector >> (BM_EXTENT_SIZE_B-9));
	struct bm_extent* bm_ext;
	int i;

	wait_event(mdev->al_wait, (bm_ext = _bme_get(mdev,enr)) );

	if(test_bit(BME_LOCKED,&bm_ext->flags)) return;

	for(i=0;i<SM;i++) {
		wait_event(mdev->al_wait, !_is_in_al(mdev,enr*SM+i) );
	}

	set_bit(BME_LOCKED,&bm_ext->flags);
}

void drbd_rs_complete_io(drbd_dev* mdev, sector_t sector)
{
	unsigned int enr = (sector >> (BM_EXTENT_SIZE_B-9));
	struct bm_extent* bm_ext;

	spin_lock_irq(&mdev->al_lock);
	bm_ext = (struct bm_extent*) lc_find(mdev->resync,enr);
	if(!bm_ext) {
		spin_unlock_irq(&mdev->al_lock);
		ERR("drbd_rs_complete_io() called, but extent not found");
		return;
	}

	if( lc_put(mdev->resync,(struct lc_element *)bm_ext) == 0 ) {
		clear_bit(BME_LOCKED,&bm_ext->flags);
		clear_bit(BME_NO_WRITES,&bm_ext->flags);
		wake_up(&mdev->al_wait);
	}

	spin_unlock_irq(&mdev->al_lock);
}

