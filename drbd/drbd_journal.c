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

#define SIGNUM(x, y) ((x > y) - (x < y))

static bool circular_in_order(u64 live_start, u64 live_end, u64 next_entry)
{
	return live_start == live_end ||
		SIGNUM(live_start, live_end) * SIGNUM(live_end, next_entry) * SIGNUM(next_entry, live_start) > 0;
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
	atomic64_set(&bdev->journal.live_start, 0);
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

	bdev->journal_dax_dev = NULL;
	bdev->journal.memory_map = NULL;
	printk("## wake journal wait; closing\n");
	wake_up(&bdev->journal.journal_wait);
}

/**
 * Claim next journal entry.
 *
 * May block waiting for space to become free if the journal has insufficient
 * space.
 *
 * drbd_journal_next and drbd_journal_commit require external synchronization
 * for a given device.
 *
 * The data location to write to is set on peer_req.
 */
int drbd_journal_next(struct drbd_device *device, struct drbd_peer_request *peer_req)
{
	struct drbd_journal *journal = &device->ldev->journal;
	struct drbd_connection *connection = peer_req->peer_device->connection;
	struct journal_entry_on_disk *entry;

	if (journal->live_end + entry_with_data_size(peer_req) > entry_capacity(journal)) {
		journal->live_end = 0;
	}

	entry = entry_from_offset(journal, journal->live_end);
	peer_req->next_entry_offset = journal->live_end + entry_with_data_size(peer_req);

	/* wait until there is sufficient space */
	drbd_info(device, "## journal wait; start %lld, need space from %llu to %llu\n",
		atomic64_read(&journal->live_start), journal->live_end, peer_req->next_entry_offset);
	wait_event(journal->journal_wait,
		circular_in_order(atomic64_read(&journal->live_start), journal->live_end, peer_req->next_entry_offset)
			|| !journal->memory_map
			|| connection->cstate[NOW] < C_CONNECTED);
	if (journal->memory_map && connection->cstate[NOW] >= C_CONNECTED) {
		drbd_info(device, "## journal wait done\n");
	} else {
		drbd_info(device, "## journal wait canceled\n");
		return -ECANCELED;
	}

	memset(entry, 0, sizeof(*entry));
	entry->next = cpu_to_be64(peer_req->next_entry_offset);
	entry->dagtag_sector = cpu_to_be64(peer_req->dagtag_sector);
	entry->sector = cpu_to_be64(peer_req->i.sector);
	entry->size = cpu_to_be64(peer_req->i.size);
	entry->data_size = cpu_to_be64(peer_req->data_size);

	peer_req->data = ((char *) entry) + JOURNAL_ENTRY_SIZE;
	return 0;
}

static void insert_interval(struct drbd_journal *journal, struct list_head *list, sector_t sector, sector_t end_sector)
{
	struct drbd_journal_interval *journal_interval;

	/* TODO: handle allocation failure */
	/* TODO: use mempool */
	journal_interval = kzalloc(sizeof(struct drbd_journal_interval), GFP_NOIO);
	drbd_clear_interval(&journal_interval->i);
	list_add_tail(&journal_interval->list, list);
	journal_interval->i.sector = sector;
	journal_interval->i.size = (end_sector - sector) << SECTOR_SHIFT;
	drbd_insert_interval(&journal->intervals, &journal_interval->i);
}

static void replace_interval(struct drbd_journal *journal, struct drbd_interval *existing_interval, sector_t sector, sector_t end_sector)
{
	drbd_remove_interval(&journal->intervals, existing_interval);
	drbd_clear_interval(existing_interval);
	existing_interval->sector = sector;
	existing_interval->size = (end_sector - sector) << SECTOR_SHIFT;
	drbd_insert_interval(&journal->intervals, existing_interval);
}

static void remove_interval(struct drbd_journal *journal, struct drbd_interval *existing_interval)
{
	struct drbd_journal_interval *existing_journal_interval =
		container_of(existing_interval, struct drbd_journal_interval, i);
	drbd_remove_interval(&journal->intervals, existing_interval);
	drbd_clear_interval(existing_interval);
	list_del(&existing_journal_interval->list);
	kfree(existing_journal_interval);
}

/**
 * Commit journal entry.
 */
void drbd_journal_commit(struct drbd_device *device, struct drbd_peer_request *peer_req)
{
	struct drbd_journal *journal = &device->ldev->journal;
	struct journal_header_on_disk *header = journal->memory_map;
	__be64 new_live_end = cpu_to_be64(peer_req->next_entry_offset);
	struct drbd_interval *existing_interval;
	sector_t peer_req_sector = peer_req->i.sector;
	sector_t peer_req_end = peer_req_sector + (peer_req->i.size >> SECTOR_SHIFT);

	/* ensure entry and data are persisted */
	wmb();

	/* commit by updating header */
	memcpy_flushcache(&header->live_end, &new_live_end, sizeof(header->live_end));

	journal->live_end = peer_req->next_entry_offset;

	list_add_tail(&peer_req->journal_order, &journal->live_entries);

	/* adjust existing intervals to avoid overlaps */
	while ((existing_interval = drbd_find_overlap(&journal->intervals, peer_req_sector, peer_req->i.size))) {
		sector_t existing_interval_sector = existing_interval->sector;
		sector_t existing_interval_end = existing_interval_sector + (existing_interval->size >> SECTOR_SHIFT);
		drbd_info(device, "## drbd_journal_commit new (%llu, %llu) existing (%llu, %llu)\n",
			  (unsigned long long) peer_req_sector, (unsigned long long) peer_req->i.size,
			  (unsigned long long) existing_interval_sector, (unsigned long long) existing_interval->size);
		if (existing_interval_sector < peer_req_sector) {
			if (existing_interval_end <= peer_req_end) {
				/* new interval overlaps end of existing interval, shorten existing interval */
				replace_interval(journal, existing_interval, existing_interval_sector, peer_req_sector);
			} else {
				/* new interval contained in existing interval, punch hole in existing interval */
				struct drbd_journal_interval *existing_journal_interval =
					container_of(existing_interval, struct drbd_journal_interval, i);

				replace_interval(journal, existing_interval, existing_interval_sector, peer_req_sector);

				insert_interval(journal, &existing_journal_interval->list, peer_req_end, existing_interval_end);
			}
		} else {
			if (existing_interval_end <= peer_req_end) {
				/* new interval overlaps entire existing interval, remove existing interval */
				remove_interval(journal, existing_interval);
			} else {
				/* new interval overlaps start of existing interval, shift start of existing interval */
				replace_interval(journal, existing_interval, peer_req_end, existing_interval_end);
			}
		}
	}

	insert_interval(journal, &peer_req->journal_intervals, peer_req_sector, peer_req_end);

	drbd_info(device, "## drbd_journal_commit journal interval tree now contains:\n");
	drbd_for_each_overlap(existing_interval, &journal->intervals, 0, 1 << 30) {
		drbd_info(device, "## drbd_journal_commit sector %llu size %llu\n",
			(unsigned long long) existing_interval->sector,
			(unsigned long long) existing_interval->size);
	}
}

/**
 * Drop entries up to and including the given request.
 */
void drbd_journal_drop_until(struct drbd_device *device, u64 next_entry_offset)
{
	struct drbd_journal *journal = &device->ldev->journal;
	struct journal_header_on_disk *header = journal->memory_map;
	__be64 new_live_start = cpu_to_be64(next_entry_offset);

	memcpy_flushcache(&header->live_start, &new_live_start, sizeof(header->live_start));

	atomic64_set(&journal->live_start, next_entry_offset);

	/* TODO: remove from interval tree (need synchronization) and free struct drbd_journal_interval objects */

	drbd_info(device, "## wake journal wait; new start %lld\n", next_entry_offset);
	wake_up(&journal->journal_wait);
}
