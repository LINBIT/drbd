/*
   drbd_journal.c

   This file is part of DRBD by Philipp Reisner and Lars Ellenberg.

   Copyright (C) 2004-2019, LINBIT Information Technologies GmbH.
   Copyright (C) 2004-2019, Philipp Reisner <philipp.reisner@linbit.com>.
   Copyright (C) 2004-2019, Lars Ellenberg <lars.ellenberg@linbit.com>.
   Copyright (C) 2019, Joel Colledge <joel.colledge@linbit.com>.

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

#include <linux/dax.h>
#include <linux/pfn_t.h>

#include "drbd_int.h"
#include "drbd_meta_data.h"

#define JOURNAL_HEADER_SIZE (sizeof(struct journal_header_on_disk))
#define JOURNAL_ENTRY_SIZE (sizeof(struct journal_entry_on_disk))

static struct journal_entry_on_disk *entry_from_offset(struct drbd_journal *journal, u64 offset)
{
	return (struct journal_entry_on_disk *) (((char *) journal->memory_map) + JOURNAL_HEADER_SIZE + offset);
}

static u64 entry_with_data_size(struct drbd_peer_request *peer_req)
{
	return JOURNAL_ENTRY_SIZE + peer_req->data_size;
}

static u64 entry_capacity(const struct drbd_journal *journal) {
	return (journal->known_size << SECTOR_SHIFT) - JOURNAL_HEADER_SIZE;
}

int drbd_journal_open(struct drbd_backing_dev *bdev)
{
	int r;
	int id;
	long nr_pages_request;
	long nr_pages_alloc;
	pfn_t pfn;

	bdev->journal_dax_dev = dax_get_by_host(bdev->journal_bdev->bd_disk->disk_name);
	bdev->journal.known_size = i_size_read(bdev->journal_bdev->bd_inode) >> 9;

	id = dax_read_lock();

	nr_pages_request = bdev->journal.known_size >> (PAGE_SHIFT - SECTOR_SHIFT);
	nr_pages_alloc = dax_direct_access(bdev->journal_dax_dev, 0, nr_pages_request, &bdev->journal.memory_map, &pfn);
	printk("## dax_direct_access alloc: %ld %p %llx\n", nr_pages_alloc, bdev->journal.memory_map, pfn.val);

	if (nr_pages_alloc < 0) {
		bdev->journal.memory_map = NULL;
		r = nr_pages_alloc;
		goto err;
	}

	if (!pfn_t_has_page(pfn)) {
		bdev->journal.memory_map = NULL;
		r = -EOPNOTSUPP;
		goto err;
	}

	if (nr_pages_alloc != nr_pages_request) {
		// TODO: Add vmap logic from dm-writecache.c:persistent_memory_claim
		bdev->journal.memory_map = NULL;
		r = -ENOMEM;
		goto err;
	}

	dax_read_unlock(id);

	/* TODO: read from journal */
	bdev->journal.live_end = 0;

	return 0;

	// TODO: when finished: if (used vmap logic) vunmap

err:
	dax_read_unlock(id);
	return r;
}

void drbd_journal_close(struct drbd_backing_dev *bdev)
{
	put_dax(bdev->journal_dax_dev);
}

/**
 * Claim next journal entry.
 *
 * May block waiting for space to become free if the journal has insufficient
 * space.
 *
 * The data location to write to is set on peer_req.
 */
int drbd_journal_next(struct drbd_device *device, struct drbd_peer_request *peer_req)
{
	struct drbd_journal *journal = &device->ldev->journal;
	struct journal_entry_on_disk *entry;
	u64 next_entry_offset;

	if (journal->live_end + entry_with_data_size(peer_req) > entry_capacity(journal)) {
		journal->live_end = 0;
	}

	entry = entry_from_offset(journal, journal->live_end);
	next_entry_offset = journal->live_end + entry_with_data_size(peer_req);

	memset(entry, 0, sizeof(*entry));
	/* TODO: wait if insufficient space */
	entry->next = cpu_to_be64(next_entry_offset);
	entry->dagtag_sector = cpu_to_be64(peer_req->dagtag_sector);
	entry->sector = cpu_to_be64(peer_req->i.sector);
	entry->size = cpu_to_be64(peer_req->i.size);
	entry->data_size = cpu_to_be64(peer_req->data_size);

	peer_req->data = ((char *) entry) + JOURNAL_ENTRY_SIZE;
	return 0;
}

/**
 * Commit journal entry.
 */
void drbd_journal_commit(struct drbd_device *device, struct drbd_peer_request *peer_req)
{
	struct drbd_journal *journal = &device->ldev->journal;
	struct journal_header_on_disk *header = journal->memory_map;
	struct journal_entry_on_disk *entry = entry_from_offset(journal, journal->live_end);

	/* ensure entry and data are persisted */
	wmb();

	/* commit by updating header */
	memcpy_flushcache(&header->live_end, &entry->next, sizeof(header->live_end));

	journal->live_end += entry_with_data_size(peer_req);
}

/**
 * Drop entries up to and including the given request.
 */
void drbd_journal_drop_until(struct drbd_device *device, void *peer_req_data)
{
	struct drbd_journal *journal = &device->ldev->journal;
	struct journal_header_on_disk *header = journal->memory_map;
	struct journal_entry_on_disk *entry =
		(struct journal_entry_on_disk *) (((char *) peer_req_data) - JOURNAL_ENTRY_SIZE);

	memcpy_flushcache(&header->live_start, &entry->next, sizeof(header->live_start));
}
