// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2017, LINBIT HA-Solutions GmbH.
 */

/*
 * In case DRBD's meta-data resides in persistent memory do a few things
 * different.
 *
 * 1 direct access the bitmap in place. Do not load it into DRAM, do not
 *   write it back from DRAM.
 * 2 Use a better fitting format for the on-disk activity log. Instead of
 *   writing transactions, the unmangled LRU-cache hash table is there.
 */

#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/dax.h>
#include <linux/libnvdimm.h>
#include <linux/blkdev.h>
#include <linux/sizes.h>
#include "drbd_int.h"
#include "drbd_dax_pmem.h"
#include "drbd_meta_data.h"

/*
 * Unit conversions for addressing the metadata area through DAX.
 * DRBD keeps metadata offsets in sectors, dax_direct_access() works in pages.
 */
static pgoff_t md_sector_to_pgoff(sector_t sector)
{
	return sector >> (PAGE_SHIFT - SECTOR_SHIFT);
}

static long md_sectors_to_pages(sector_t nr_sectors)
{
	return nr_sectors >> (PAGE_SHIFT - SECTOR_SHIFT);
}

/* Signed, since the bitmap offset relative to the superblock may be negative. */
static long md_sector_offset_to_bytes(long sector_offset)
{
	return sector_offset * SECTOR_SIZE;
}

static int map_superblock_for_dax(struct drbd_backing_dev *bdev, struct dax_device *dax_dev)
{
	long want = 1;
	pgoff_t pgoff = md_sector_to_pgoff(bdev->md.md_offset);
	void *kaddr;
	long len;
	int id;

	id = dax_read_lock();
	len = dax_direct_access(dax_dev, pgoff, want, DAX_ACCESS, &kaddr, NULL);
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
	struct dax_device *dax_dev;
	int err;
	u64 part_off;

	dax_dev = fs_dax_get_by_bdev(bdev->md_bdev, &part_off, NULL, NULL);
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
	long want = md_sectors_to_pages(drbd_md_last_sector(bdev) + 1 - first_sector);
	pgoff_t pgoff = md_sector_to_pgoff(first_sector);
	long md_offset_byte = md_sector_offset_to_bytes(bdev->md.md_offset - first_sector);
	long al_offset_byte = md_sector_offset_to_bytes(al_sector - first_sector);
	void *kaddr;
	long len;
	int id;

	id = dax_read_lock();
	len = dax_direct_access(dax_dev, pgoff, want, DAX_ACCESS, &kaddr, NULL);
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
	/* The activity log area holds the magic followed by the slots. */
	int i, al_slots = device->ldev->md.al_size_4k * (SZ_4K / sizeof(*slots)) - 1;

	al_on_pmem->magic = cpu_to_be32(DRBD_AL_PMEM_MAGIC);
	/*
	 * Initialize all slots rather than just the configured number in case
	 * the configuration is later changed.
	 */
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

	return md_on_pmem + md_sector_offset_to_bytes(bdev->md.bm_offset);
}
