/*
   drbd_dax.c

   This file is part of DRBD by Philipp Reisner and Lars Ellenberg.

   Copyright (C) 2017, LINBIT HA-Solutions GmbH.

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
	unsigned long len;
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
	unsigned long len;
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
