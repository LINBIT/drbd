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

#define AL_EXTENT_SIZE_B 22             // One extend represents 4M Storage
#define AL_EXTENT_SIZE (1<<AL_EXTENT_SIZE_B)
#define AL_FREE (-1)

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
	spin_unlock(&mdev->al_lock);
	/* TODO allocate some 12.5% (=1/8) extents more and put
	   them onto the free list first :)
	 */
}

void drbd_al_free(struct Drbd_Conf *mdev)
{
	kfree(mdev->al_extents);
	mdev->al_extents=0;
	mdev->al_nr_extents=0;
}

static int al_hash_fn( unsigned int enr, int max )
{
	return enr % max;
}

STATIC struct drbd_extent * drbd_al_find(struct Drbd_Conf *mdev, 
					 unsigned int enr)
{
	struct drbd_extent *extent;
	int i;

	i = al_hash_fn( enr , mdev->al_nr_extents );
	extent = mdev->al_extents + i;
	while(extent && extent->extent_nr != enr)
		extent = extent->hash_next;
	return extent;
}

STATIC struct drbd_extent * drbd_al_evict(struct Drbd_Conf *mdev)
{
	struct list_head *le;
	struct drbd_extent *extent, *p;
	int i;

	le=mdev->al_lru.prev;
	list_del(le);
	extent=list_entry(le, struct drbd_extent,accessed);
	D_ASSERT(extent->pending_ios == 0);

	i = al_hash_fn( extent->extent_nr , mdev->al_nr_extents );
	p = mdev->al_extents + i;
	if( p == extent) {
		p = extent->hash_next;
		if( p == NULL) return extent;
		// move the next in hash table (p) to first position (extent) !
		extent->extent_nr = p->extent_nr;
		extent->pending_ios = p->pending_ios;
		extent->hash_next = p->hash_next;
		le = p->accessed.prev; // Fixing accessed list here!
		list_del(&p->accessed);
		list_add(&extent->accessed,le);
		return p;
	}
	do {
		if( p->hash_next == extent ) {
			p->hash_next = extent->hash_next;
			return extent;
		}
		p=p->hash_next;
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
	struct drbd_extent *extent, *n;
	int i;

	i = al_hash_fn( enr , mdev->al_nr_extents );
	extent = mdev->al_extents + i;
	if (extent->extent_nr == AL_FREE) {
		list_del(&extent->accessed);
		extent->hash_next = NULL;
	} else {
		n = drbd_al_get(mdev);
		if( n != extent) {
			n->hash_next = extent->hash_next;
			extent->hash_next = n;
			extent = n;
		}
		// else { good luck, we got this slot. }
	}
	extent->extent_nr = enr;
	list_add(&extent->accessed,&mdev->al_lru);

	return extent;
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
		extent = drbd_al_add(mdev,enr);
		mdev->al_writ_cnt++;
		update_al=1;
	}

	extent->pending_ios++;
	
	spin_unlock(&mdev->al_lock);

	/* TODO
	if( update_al ) {
		drbd_md_write_al();
		if(cstate != Connected) update_on_disk_bitmap();
	}
	*/
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

	extent->pending_ios--;

	spin_unlock(&mdev->al_lock);
}
