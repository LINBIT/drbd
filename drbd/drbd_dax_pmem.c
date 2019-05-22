// SPDX-License-Identifier: GPL-2.0-or-later
/*
   drbd_dax.c

   This file is part of DRBD by Philipp Reisner and Lars Ellenberg.

   Copyright (C) 2017, LINBIT HA-Solutions GmbH.


 */

/*
  In case DRBD's meta-data resides in persistent memory do a few things
   different.

   1 direct access the bitmap in place. Do not load it into DRAM, do not
     write it back from DRAM.
   2 Use a better fitting format for the on-disk activity log. Instead of
     writing transactions, the unmangled LRU-cache hash table is there.
*/

#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/dax.h>
#include <linux/pfn_t.h>
#include <linux/libnvdimm.h>
#include <linux/blkdev.h>
#include "drbd_int.h"
#include "drbd_dax_pmem.h"
#include "drbd_meta_data.h"

static int map_superblock_for_dax(struct drbd_backing_dev *bdev, struct dax_device *dax_dev)
{
	long want = 1;
	pgoff_t pgoff = bdev->md.md_offset >> (PAGE_SHIFT - SECTOR_SHIFT);
	void *kaddr;
	long len;
	pfn_t pfn_unused; /* before 4.18 it is required to pass in non-NULL */
	int id;

	id = dax_read_lock();
	len = dax_direct_access(dax_dev, pgoff, want, &kaddr, &pfn_unused);
	dax_read_unlock(id);

	if (len < want)
		return -EIO;

	bdev->md_on_pmem = kaddr;

	return 0;
}

/**
 * drbd_dax_open() - Open device for dax and map metadata superblock
 * @bdev: backing device to be opened
 */
int drbd_dax_open(struct drbd_backing_dev *bdev)
{
	const char *disk_name = bdev->md_bdev->bd_disk->disk_name;
	struct dax_device *dax_dev;
	int err;

	if (!blk_queue_dax(bdev->md_bdev->bd_disk->queue))
		return -ENODEV;

	dax_dev = dax_get_by_host(disk_name);
	if (!dax_dev)
		return -ENODEV;

	err = map_superblock_for_dax(bdev, dax_dev);
	if (!err)
		bdev->dax_dev = dax_dev;
	else
		put_dax(dax_dev);

	return err;
}

void drbd_dax_close(struct drbd_backing_dev *bdev)
{
	put_dax(bdev->dax_dev);
}

/**
 * drbd_dax_map() - Map metadata for dax
 * @bdev: backing device whose metadata is to be mapped
 */
int drbd_dax_map(struct drbd_backing_dev *bdev)
{
	struct dax_device *dax_dev = bdev->dax_dev;
	sector_t first_sector = drbd_md_first_sector(bdev);
	sector_t al_sector = bdev->md.md_offset + bdev->md.al_offset;
	long want = (drbd_md_last_sector(bdev) + 1 - first_sector) >> (PAGE_SHIFT - SECTOR_SHIFT);
	pgoff_t pgoff = first_sector >> (PAGE_SHIFT - SECTOR_SHIFT);
	long md_offset_byte = (bdev->md.md_offset - first_sector) << SECTOR_SHIFT;
	long al_offset_byte = (al_sector - first_sector) << SECTOR_SHIFT;
	void *kaddr;
	long len;
	pfn_t pfn_unused; /* before 4.18 it is required to pass in non-NULL */
	int id;

	id = dax_read_lock();
	len = dax_direct_access(dax_dev, pgoff, want, &kaddr, &pfn_unused);
	dax_read_unlock(id);

	if (len < want)
		return -EIO;

	bdev->md_on_pmem = kaddr + md_offset_byte;
	bdev->al_on_pmem = kaddr + al_offset_byte;

	return 0;
}

void drbd_dax_al_update(struct drbd_device *device, struct lc_element *al_ext)
{
	struct al_on_pmem *al_on_pmem = device->ldev->al_on_pmem;
	__be32 *slot = &al_on_pmem->slots[al_ext->lc_index];

	*slot = cpu_to_be32(al_ext->lc_new_number);
	arch_wb_cache_pmem(slot, sizeof(*slot));
}


void drbd_dax_al_begin_io_commit(struct drbd_device *device)
{
	struct lc_element *e;

	spin_lock_irq(&device->al_lock);

	list_for_each_entry(e, &device->act_log->to_be_changed, list)
		drbd_dax_al_update(device, e);

	lc_committed(device->act_log);

	spin_unlock_irq(&device->al_lock);
}

int drbd_dax_al_initialize(struct drbd_device *device)
{
	struct al_on_pmem *al_on_pmem = device->ldev->al_on_pmem;
	__be32 *slots = al_on_pmem->slots;
	int i, al_slots = (device->ldev->md.al_size_4k << (12 - 2)) - 1;

	al_on_pmem->magic = cpu_to_be32(DRBD_AL_PMEM_MAGIC);
	/* initialize all slots rather than just the configured number in case
	 * the configuration is later changed */
	for (i = 0; i < al_slots; i++) {
		unsigned int extent_nr = i < device->act_log->nr_elements ?
			lc_element_by_index(device->act_log, i)->lc_number :
			LC_FREE;
		slots[i] = cpu_to_be32(extent_nr);
	}

	return 0;
}

void *drbd_dax_bitmap(struct drbd_device *device, unsigned long want)
{
	struct drbd_backing_dev *bdev = device->ldev;
	unsigned char *md_on_pmem = (unsigned char *)bdev->md_on_pmem;

	return md_on_pmem + (long)bdev->md.bm_offset * SECTOR_SIZE;
}
