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
#define AL_FREE (-1)
#define AL_EXTENTS_PP 122

struct al_transaction {
	u32       magic;
	u32       tr_number;
	u32       updated_extents[3];
	u32       cyclic_extents[AL_EXTENTS_PP];
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


void drbd_al_init(struct Drbd_Conf *mdev)
{
	int i;
	struct drbd_extent *extents;

	if(mdev->al_nr_extents == mdev->sync_conf.al_extents) return;

	extents = kmalloc(sizeof(struct drbd_extent) *
			  mdev->sync_conf.al_extents,GFP_KERNEL);

	if(!extents) {
		printk(KERN_ERR DEVICE_NAME
		       "%d: can not kmalloc() activity log\n",
		       (int)(mdev-drbd_conf));
		return;
	}

	if(!mdev->al_tr_buffer) {
		mdev->al_tr_buffer=kmalloc(sizeof(struct al_transaction),
					   GFP_KERNEL);
		if(!mdev->al_tr_buffer) {
			printk(KERN_ERR DEVICE_NAME
			       "%d: can not kmalloc() al_tr_buffer\n",
			       (int)(mdev-drbd_conf));
			return;
		}
	}

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
	spin_unlock(&mdev->al_lock);	
}

void drbd_al_free(struct Drbd_Conf *mdev)
{
	if(mdev->al_extents) kfree(mdev->al_extents);
	if(mdev->al_tr_buffer) kfree(mdev->al_tr_buffer);
	mdev->al_extents=0;
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
	D_ASSERT(extent->pending_ios == 0);

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
		extent->extent_nr = AL_FREE;
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

void drbd_al_write_transaction(struct Drbd_Conf *mdev)
{
	/* completely unfinished */
	int i,n,c;
	unsigned int t;
	struct al_transaction* buffer;
	unsigned int extent_nr;
	u32 xor_sum=0;

	spin_lock(&mdev->al_lock);
	t = mdev->al_tr_number++;
	//c = mdev->al_cycle++;
	c = 0;
	spin_unlock(&mdev->al_lock);

	while(1) {
		spin_lock(&mdev->al_lock);
		buffer = mdev->al_tr_buffer;
		mdev->al_tr_buffer = 0;
		spin_unlock(&mdev->al_lock);
		if(buffer) break;
		schedule_timeout(HZ / 10);
	}
	buffer->magic = __constant_cpu_to_be32(DRBD_MAGIC);
	buffer->tr_number = cpu_to_be32(t);
	for(i=0;i<3;i++) {
		n = mdev->al_updates[i];
		if(n != -1) {
			extent_nr = mdev->al_extents[n].extent_nr;
#if 0	/* Use this printf with the test_al.pl program */
			printk(KERN_ERR DEVICE_NAME
			       "%d: T%03d S%03d=E%06d\n",(int)(mdev-drbd_conf),
			       t, n, extent_nr);
#endif
			buffer->updated_extents[i] = cpu_to_be32(extent_nr);
			xor_sum ^= extent_nr;
		}
	}

	for(i=0;i<AL_EXTENTS_PP;i++) {
		extent_nr = mdev->al_extents[i].extent_nr;
		buffer->cyclic_extents[i] = cpu_to_be32(extent_nr);
		xor_sum ^= extent_nr;
	}
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

		extent = drbd_al_add(mdev,enr);
		mdev->al_writ_cnt++;

		update_al=1;
	}

	extent->pending_ios++;
	
	spin_unlock(&mdev->al_lock);

	if( update_al ) {
		drbd_al_write_transaction(mdev);
		// TODO if(cstate != Connected) update_on_disk_bitmap();
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
		printk(KERN_ERR DEVICE_NAME
		       "%d: drbd_al_complete_io() called on incative extent\n",
		       (int)(mdev-drbd_conf));
		return;
	}

	D_ASSERT( extent->pending_ios > 0);
	extent->pending_ios--;

	spin_unlock(&mdev->al_lock);
}
