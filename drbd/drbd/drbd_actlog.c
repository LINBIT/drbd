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

// integer division, round _UP_ to the next integer
#define div_ceil(A,B) ( (A)/(B) + ((A)%(B) ? 1 : 0) )
// usual integer division
#define div_floor(A,B) ( (A)/(B) )

#define AL_EXTENT_SIZE_B 22             // One extent represents 4M Storage
#define AL_EXTENT_SIZE (1<<AL_EXTENT_SIZE_B)
#define AL_FREE (-1)
#define AL_EXTENTS_PT 59

struct al_transaction {
	u32       magic;
	u32       tr_number;
	struct { 
		u32 pos;
		u32 extent; } updated[3],cyclic[AL_EXTENTS_PT];
	u32       xor_sum;      
       // I do not believe that all storage medias can guarantee atomic
       // 512 byte write operations. When the journal is read, only
       // transactions with correct xor_sums are considered.
};     // sizeof() = 512 byte

struct drbd_extent {
	struct list_head accessed;
	struct drbd_extent *hash_next;
	unsigned int extent_nr;
	unsigned int pending_ios;
};

STATIC void drbd_al_write_transaction(struct Drbd_Conf *mdev);
STATIC void drbd_al_set(struct Drbd_Conf*, unsigned int, int);
STATIC int drbd_al_fixup_hash_next(struct Drbd_Conf*);
STATIC void drbd_al_setup_bitmap(struct Drbd_Conf *mdev);
STATIC void drbd_update_on_disk_bitmap(struct Drbd_Conf *,unsigned int);
STATIC void drbd_read_bitmap(struct Drbd_Conf *mdev);

void drbd_al_init(struct Drbd_Conf *mdev)
{
	int i;
	struct drbd_extent *extents;

	if(mdev->al_nr_extents == mdev->sync_conf.al_extents) return;

	extents = kmalloc(sizeof(struct drbd_extent) *
			  mdev->sync_conf.al_extents,GFP_KERNEL);

	if(!extents) {
		ERR("can not kmalloc() activity log\n");
		return;
	}

	if(!mdev->md_io_bh) {
		struct page * page = alloc_page(GFP_KERNEL);
		ERR_IF(!page) return;
		mdev->md_io_bh=kmem_cache_alloc(bh_cachep, GFP_KERNEL);
		ERR_IF(!mdev->md_io_bh) {
			__free_page(page);
			return;
		}
		drbd_init_bh(mdev->md_io_bh,512);
		set_bh_page(mdev->md_io_bh,page,0);
	}

	down(&mdev->md_io_mutex);
	spin_lock(&mdev->al_lock);
	INIT_LIST_HEAD(&mdev->al_lru);
	INIT_LIST_HEAD(&mdev->al_free);
	for(i=0;i<mdev->sync_conf.al_extents;i++) {
		extents[i].extent_nr=AL_FREE;
		extents[i].hash_next=0;
		extents[i].pending_ios=0;
		list_add(&extents[i].accessed,&mdev->al_free);
	}
	mdev->al_nr_extents=mdev->sync_conf.al_extents; 
	if(mdev->al_extents) kfree(mdev->al_extents);
	mdev->al_extents = extents;
	mdev->al_tr_number = 0;
	mdev->al_tr_cycle = 0;
	mdev->al_tr_pos = 0;
	spin_unlock(&mdev->al_lock);
	up(&mdev->md_io_mutex);
}

void drbd_al_free(struct Drbd_Conf *mdev)
{
	if(mdev->al_extents) kfree(mdev->al_extents);
	if(mdev->md_io_bh) {
		__free_page(mdev->md_io_bh->b_page);
		kmem_cache_free(bh_cachep, mdev->md_io_bh);
	}
	mdev->al_extents=0;
	mdev->md_io_bh=0;
	mdev->al_nr_extents=0;
}

static struct drbd_extent *al_hash_fn(struct Drbd_Conf *mdev, unsigned int enr)
{
	return mdev->al_extents + ( enr % mdev->al_nr_extents );
}


/* When you add an extent (and most probabely remove an other extent)
   to the hash table, you can at most modifiy 3 slots in the hash table!
   drbd_al_add() can only change the extent number in two slots,
   drbd_al_evict() might change the extent number in one slot. Gives 3. */
static void al_mark_update(struct Drbd_Conf *mdev, struct drbd_extent *slot)
{
	int i;

	for(i=0;i<3;i++) {
		if(mdev->al_updates[i] == -1) {
			mdev->al_updates[i] = slot - mdev->al_extents;
			break;
		}
	}
}

STATIC struct drbd_extent * drbd_al_find(struct Drbd_Conf *mdev, 
					 unsigned int enr)
{
	struct drbd_extent *extent;

	extent = al_hash_fn(mdev, enr);
	while(extent && extent->extent_nr != enr)
		extent = extent->hash_next;
	return extent;
}

STATIC void drbd_al_move_extent(struct drbd_extent *from, 
				struct drbd_extent *to)
{
	struct list_head *le;

	to->extent_nr = from->extent_nr;
	to->pending_ios = from->pending_ios;
	to->hash_next = from->hash_next;
	le = from->accessed.prev; // Fixing accessed list here!
	list_del(&from->accessed);
	list_add(&to->accessed,le);
}

STATIC struct drbd_extent * drbd_al_evict(struct Drbd_Conf *mdev)
{
	struct list_head *le;
	struct drbd_extent *extent, *slot;

	le=mdev->al_lru.prev;
	list_del(le);
	extent=list_entry(le, struct drbd_extent,accessed);
	if(extent->pending_ios) { 
		// Ouch! In the least recently used extent there are still
		// pending wirte requests. We have to sleep a bit...
		return 0;
	}

	slot = al_hash_fn( mdev, extent->extent_nr);
	if( slot == extent) {
		slot = extent->hash_next;
		if( slot == NULL) return extent;
		// move the next in hash table (=slot) to its slot (=extent)
		drbd_al_move_extent(slot,extent);
		al_mark_update(mdev, extent);

		return slot;
	}
	do {
		if( slot->hash_next == extent ) {
			slot->hash_next = extent->hash_next;
			return extent;
		}
		slot=slot->hash_next;
	} while(1);
}

STATIC struct drbd_extent * drbd_al_get(struct Drbd_Conf *mdev)
{
	struct list_head *le;
	struct drbd_extent *extent;

	if(list_empty(&mdev->al_free)) {
		extent=drbd_al_evict(mdev);
		if(extent) {
			mdev->al_evicted = extent->extent_nr;
			extent->extent_nr = AL_FREE;
		}
		return extent;
	}

	le=mdev->al_free.next;
	list_del(le);
	extent=list_entry(le, struct drbd_extent,accessed);

	return extent;
}

STATIC struct drbd_extent * drbd_al_add(struct Drbd_Conf *mdev, 
					unsigned int enr)
{
	struct drbd_extent *slot, *n, *a;

	slot = al_hash_fn( mdev, enr );
	if (slot->extent_nr == AL_FREE) {
		list_del(&slot->accessed);
		slot->hash_next = NULL;
		goto have_slot;
	}

	n = drbd_al_get(mdev);
	if(!n) return 0;

	if ( n == slot) {
		// we got the slot we wanted 
		goto have_slot;
	}

	a = al_hash_fn( mdev, slot->extent_nr );
	if( a != slot ) {
		// our extent is a better fit for this slot
		drbd_al_move_extent(slot,n);
		al_mark_update(mdev, n);
		// fix the hash_next pointer to the element in slot
		a = al_hash_fn( mdev, n->extent_nr );
		while(a->hash_next != slot) a=a->hash_next;
		a->hash_next = n;
		
		goto have_slot;
	}

	// chain our extent behind this slot 
	n->hash_next = slot->hash_next;
	slot->hash_next = n;
	slot = n;

 have_slot:
	slot->extent_nr = enr;
	al_mark_update(mdev, slot);
	list_add(&slot->accessed,&mdev->al_lru);

	return slot;
}

void drbd_al_begin_io(struct Drbd_Conf *mdev, sector_t sector)
{
	unsigned int enr = (sector >> (AL_EXTENT_SIZE_B-9));
	struct drbd_extent *extent;
	int update_al=0;

	spin_lock(&mdev->al_lock);

	extent = drbd_al_find(mdev,enr);

	if(extent) { // we have a hit!
		list_del(&extent->accessed);
		list_add(&extent->accessed,&mdev->al_lru);
	} else { // miss, need to updated AL
		int i;
		
		for(i=0;i<3;i++) mdev->al_updates[i]=-1;
		mdev->al_evicted = AL_FREE;

		while(1) {
			extent = drbd_al_add(mdev,enr);
			if(likely(extent != 0)) break;
			spin_unlock(&mdev->al_lock);
			WARN("Have to wait for extent! "
			     "You should increase 'al-extents'\n");
			sleep_on(&mdev->al_wait);
			spin_lock(&mdev->al_lock);
		}
		mdev->al_writ_cnt++;

		update_al=1;
	}

	extent->pending_ios++;

	spin_unlock(&mdev->al_lock);

	if( update_al ) {
		if(mdev->cstate < Connected &&  mdev->al_evicted != AL_FREE ) {
			drbd_update_on_disk_bitmap(mdev,mdev->al_evicted);
		}
		drbd_al_write_transaction(mdev);
	}
}

void drbd_al_complete_io(struct Drbd_Conf *mdev, sector_t sector)
{
	unsigned int enr = (sector >> (AL_EXTENT_SIZE_B-9));
	struct drbd_extent *extent;

	spin_lock(&mdev->al_lock);

	extent = drbd_al_find(mdev,enr);

	if(!extent) {
		spin_unlock(&mdev->al_lock);
		ERR("drbd_al_complete_io() called on inactive extent\n");
		return;
	}

	D_ASSERT( extent->pending_ios > 0);
	extent->pending_ios--;

	if(extent->pending_ios == 0) {
		wake_up(&mdev->al_wait);
	}

	spin_unlock(&mdev->al_lock);
}

STATIC void drbd_al_write_transaction(struct Drbd_Conf *mdev)
{
	int i,n,mx;
	struct al_transaction* buffer;
	sector_t sector;
	unsigned int extent_nr;
	u32 xor_sum=0;

	down(&mdev->md_io_mutex); // protects md_io_buffer, al_tr_cycle, ...
	buffer = (struct al_transaction*)bh_kmap(mdev->md_io_bh);

	buffer->magic = __constant_cpu_to_be32(DRBD_MAGIC);
	buffer->tr_number = cpu_to_be32(mdev->al_tr_number);
	for(i=0;i<3;i++) {
		n = mdev->al_updates[i];
		if(n != -1) {
			extent_nr = mdev->al_extents[n].extent_nr;
#if 0	/* Use this printf with the test_al.pl program */
			ERR("T%03d S%03d=E%06d\n", 
			    mdev->al_tr_number, n, extent_nr);
#endif
		} else {
			extent_nr = AL_FREE;
		}
		buffer->updated[i].pos = cpu_to_be32(n);
		buffer->updated[i].extent = cpu_to_be32(extent_nr);
		xor_sum ^= extent_nr;
	}

	mx = min_t(int,AL_EXTENTS_PT,mdev->al_nr_extents-mdev->al_tr_cycle);
	for(i=0;i<mx;i++) {
		extent_nr = mdev->al_extents[mdev->al_tr_cycle+i].extent_nr;
		buffer->cyclic[i].pos = cpu_to_be32(mdev->al_tr_cycle+i);
		buffer->cyclic[i].extent = cpu_to_be32(extent_nr);
		xor_sum ^= extent_nr;
	}
	for(;i<AL_EXTENTS_PT;i++) {
		buffer->cyclic[i].pos = __constant_cpu_to_be32(-1);
		buffer->cyclic[i].extent = __constant_cpu_to_be32(AL_FREE);
		xor_sum ^= AL_FREE;
	}
	mdev->al_tr_cycle += AL_EXTENTS_PT;
	if(mdev->al_tr_cycle >= mdev->al_nr_extents) mdev->al_tr_cycle=0;

	buffer->xor_sum = cpu_to_be32(xor_sum);

	bh_kunmap(mdev->md_io_bh);

	sector = drbd_md_ss(mdev) + MD_AL_OFFSET + mdev->al_tr_pos ;

	drbd_set_bh(mdev, mdev->md_io_bh, sector, 512);
	set_bit(BH_Dirty, &mdev->md_io_bh->b_state);
	set_bit(BH_Lock, &mdev->md_io_bh->b_state);
	mdev->md_io_bh->b_end_io = drbd_generic_end_io;
	generic_make_request(WRITE,mdev->md_io_bh);
	wait_on_buffer(mdev->md_io_bh);

	if( ++mdev->al_tr_pos > div_ceil(mdev->al_nr_extents,AL_EXTENTS_PT) ) {
		mdev->al_tr_pos=0;
	}
	mdev->al_tr_number++;

	up(&mdev->md_io_mutex);
}

/* In case this function returns 1 == success, the caller must do
		bh_kunmap(mdev->md_io_bh);
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

	drbd_set_bh(mdev, mdev->md_io_bh, sector, 512);
	clear_bit(BH_Uptodate, &mdev->md_io_bh->b_state);
	set_bit(BH_Lock, &mdev->md_io_bh->b_state);
	mdev->md_io_bh->b_end_io = drbd_generic_end_io;
	generic_make_request(READ,mdev->md_io_bh);
	wait_on_buffer(mdev->md_io_bh);

	buffer = (struct al_transaction*)bh_kmap(mdev->md_io_bh);

	rv = ( be32_to_cpu(buffer->magic) == DRBD_MAGIC );

	for(i=0;i<3;i++) {
		xor_sum ^= be32_to_cpu(buffer->updated[i].extent);
	}
	for(i=0;i<AL_EXTENTS_PT;i++) {
		xor_sum ^= be32_to_cpu(buffer->cyclic[i].extent);
	}
	rv &= (xor_sum == be32_to_cpu(buffer->xor_sum));

	if(rv) {
		*bp = buffer;
	} else {
		bh_kunmap(mdev->md_io_bh);
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

	// Find the valid transaction in the log
	for(i=0;i<mdev->al_nr_extents;i++) {
		if(!drbd_al_read_tr(mdev,&buffer,i)) continue;
		cnr = be32_to_cpu(buffer->tr_number);
		// INFO("index %d valid tnr=%d\n",i,cnr);
		bh_kunmap(mdev->md_io_bh);
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

	i=from;
	while(1) {
		int j,pos;
		unsigned int extent_nr;
		unsigned int trn;

		rv = drbd_al_read_tr(mdev,&buffer,i);
		ERR_IF(!rv) continue;

		trn=be32_to_cpu(buffer->tr_number);

		for(j=0;j<3;j++) {
			pos = be32_to_cpu(buffer->updated[j].pos);
			extent_nr = be32_to_cpu(buffer->updated[j].extent);

			if(extent_nr == AL_FREE) continue;

			//ERR("T%03d S%03d=E%06d\n",trn, pos, extent_nr);
			drbd_al_set(mdev,extent_nr,pos);
		}

		for(j=0;j<AL_EXTENTS_PT;j++) {
			pos = be32_to_cpu(buffer->cyclic[j].pos);
			extent_nr = be32_to_cpu(buffer->cyclic[j].extent);

			if(extent_nr == AL_FREE) continue;

			drbd_al_set(mdev,extent_nr,pos);
		}
		
		bh_kunmap(mdev->md_io_bh);
		up(&mdev->md_io_mutex);

		transactions++;

		if( i == to) break;
		if( ++i > div_ceil(mdev->al_nr_extents,AL_EXTENTS_PT) ) i=0;
	}

	active_extents=drbd_al_fixup_hash_next(mdev);

	mdev->al_tr_number = to_tnr+1;
	mdev->al_tr_pos = to;
	if( ++mdev->al_tr_pos > div_ceil(mdev->al_nr_extents,AL_EXTENTS_PT) ) {
		mdev->al_tr_pos=0;
	}

	INFO("Found %d transactions (%d active extents) in activity log.\n",
	     transactions,active_extents);

	// Think if we should call drbd_read_bitmap() here...
	drbd_read_bitmap(mdev);
	// TODO only call setup_bitmap() iff it is necessary.
	drbd_al_setup_bitmap(mdev);
}

STATIC void drbd_al_set(struct Drbd_Conf *mdev,unsigned int extent_nr,int pos)
{
	struct drbd_extent *extent;

	ERR_IF(pos < 0 || pos >= mdev->al_nr_extents ) return;

	extent = mdev->al_extents + pos;
	spin_lock(&mdev->al_lock);

	list_del(&extent->accessed); // either from al_free or from al_lru
	mdev->al_extents[pos].extent_nr = extent_nr;
	list_add(&extent->accessed,&mdev->al_lru);
	extent->hash_next = 0;

	spin_unlock(&mdev->al_lock);
}

STATIC int drbd_al_fixup_hash_next(struct Drbd_Conf *mdev)
{
	struct drbd_extent *slot, *want;
	int i;
	int active_extents=0;

	spin_lock(&mdev->al_lock);

	for(i=0;i<mdev->al_nr_extents;i++) {
		slot = mdev->al_extents + i;
		if(slot->extent_nr == AL_FREE) continue;
		active_extents++;
		want = al_hash_fn(mdev,slot->extent_nr);
		if( slot != want ) {
			while (want->hash_next) want=want->hash_next;
			want->hash_next = slot;
		}
	}

	spin_unlock(&mdev->al_lock);

	return active_extents;
}

/**
 * drbd_al_setup_bitmap: Sets the bits in the bitmap that are described
 * by the active extents of the AL.
 */
STATIC void drbd_al_setup_bitmap(struct Drbd_Conf *mdev)
{
	int i;
	unsigned int enr;

	spin_lock(&mdev->al_lock);
	for(i=0;i<mdev->al_nr_extents;i++) {
		enr = mdev->al_extents[i].extent_nr;
		if(enr == AL_FREE) continue;
		mdev->rs_total +=
			bm_set_bit( mdev, 
				    enr << (AL_EXTENT_SIZE_B-9), 4<<20 , 
				    SS_OUT_OF_SYNC );
	}
	spin_unlock(&mdev->al_lock);
}

/**
 * drbd_read_bitmap: Read the whole bitmap from its on disk location.
 */
STATIC void drbd_read_bitmap(struct Drbd_Conf *mdev)
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

		drbd_set_bh(mdev, mdev->md_io_bh, sector, 512);
		clear_bit(BH_Uptodate, &mdev->md_io_bh->b_state);
		set_bit(BH_Lock, &mdev->md_io_bh->b_state);
		mdev->md_io_bh->b_end_io = drbd_generic_end_io;
		generic_make_request(READ,mdev->md_io_bh);
		wait_on_buffer(mdev->md_io_bh);

		buffer = (unsigned long *)bh_kmap(mdev->md_io_bh);

		for(buf_i=0;buf_i<want;buf_i++) {
			word = lel_to_cpu(buffer[buf_i]);
			bits += parallel_bitcount(word);
			bm[bm_i++] = word;
		}
		bh_kunmap(mdev->md_io_bh);
	}

	up(&mdev->md_io_mutex);

	mdev->rs_total = bits << (BM_BLOCK_SIZE_B - 9); // in sectors
}

/**
 * drbd_update_on_disk_bitmap: Writes a piece of the bitmap to its
 * on disk location. 
 * @enr: The extent number of the bits we should write to disk.
 *
 * TODO: Implement cleaning of the on disk bitmap somewhere...
 */
STATIC void drbd_update_on_disk_bitmap(struct Drbd_Conf *mdev,unsigned int enr)
{
	unsigned long * buffer, * bm;
	int want,buf_i,bm_words,bm_i;
	sector_t sector;

#define BM_WORDS_PER_EXTENT ( (AL_EXTENT_SIZE/BM_BLOCK_SIZE) / BITS_PER_LONG )
#define EXTENTS_PER_SECTOR  ( 512 / BM_WORDS_PER_EXTENT )

	enr = (enr & ~(EXTENTS_PER_SECTOR-1) );

	bm = mdev->mbds_id->bm;
	bm_words = mdev->mbds_id->size/sizeof(unsigned long);
	bm_i = enr * BM_WORDS_PER_EXTENT ;
	want=min_t(int,512/sizeof(long),bm_words-bm_i);

	down(&mdev->md_io_mutex); // protects md_io_buffer
	buffer = (unsigned long *)bh_kmap(mdev->md_io_bh);

	for(buf_i=0;buf_i<want;buf_i++) {
		buffer[buf_i] = cpu_to_lel(bm[bm_i++]);
	}

	bh_kunmap(mdev->md_io_bh);

	sector = drbd_md_ss(mdev) + MD_BM_OFFSET + enr;

	drbd_set_bh(mdev, mdev->md_io_bh, sector, 512);
	set_bit(BH_Dirty, &mdev->md_io_bh->b_state);
	set_bit(BH_Lock, &mdev->md_io_bh->b_state);
	mdev->md_io_bh->b_end_io = drbd_generic_end_io;
	generic_make_request(WRITE,mdev->md_io_bh);
	wait_on_buffer(mdev->md_io_bh);

	up(&mdev->md_io_mutex);

}
