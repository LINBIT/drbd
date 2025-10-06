// SPDX-License-Identifier: GPL-2.0-only
/*
   drbd_actlog.c

   This file is part of DRBD by Philipp Reisner and Lars Ellenberg.

   Copyright (C) 2003-2008, LINBIT Information Technologies GmbH.
   Copyright (C) 2003-2008, Philipp Reisner <philipp.reisner@linbit.com>.
   Copyright (C) 2003-2008, Lars Ellenberg <lars.ellenberg@linbit.com>.


 */

#include <linux/slab.h>
#include <linux/crc32c.h>
#include <linux/drbd.h>
#include <linux/dynamic_debug.h>
#include "drbd_int.h"
#include "drbd_meta_data.h"
#include "drbd_dax_pmem.h"

void *drbd_md_get_buffer(struct drbd_device *device, const char *intent)
{
	int r;
	long t;
	unsigned long t0 = jiffies;
	unsigned int warn_s = 10;

	for (;;) {
		t = wait_event_timeout(device->misc_wait,
				(r = atomic_cmpxchg(&device->md_io.in_use, 0, 1)) == 0 ||
				device->disk_state[NOW] <= D_FAILED,
				HZ * warn_s);

		if (r == 0)
			break;

		if (t != 0) {
			drbd_err(device, "Failed to get md_buffer for %s: disk state %s\n",
				 intent, drbd_disk_str(device->disk_state[NOW]));
			return NULL;
		}

		/* r != 0, t == 0: still in use, hit the timeout above.
		 * Warn, but keep trying.
		 */
		drbd_err(device, "Waited %lds on md_buffer for %s; in use by %s; still trying...\n",
			 (jiffies - t0 + HZ-1)/HZ, intent, device->md_io.current_use);
		/* reduce warn frequency */
		warn_s = max(30, warn_s + 10);
	}

	device->md_io.current_use = intent;
	device->md_io.start_jif = jiffies;
	device->md_io.submit_jif = device->md_io.start_jif - 1;
	return page_address(device->md_io.page);
}

void drbd_md_put_buffer(struct drbd_device *device)
{
	if (atomic_dec_and_test(&device->md_io.in_use))
		wake_up(&device->misc_wait);
}

void wait_until_done_or_force_detached(struct drbd_device *device, struct drbd_backing_dev *bdev,
				       unsigned int *done)
{
	long dt;

	rcu_read_lock();
	dt = rcu_dereference(bdev->disk_conf)->disk_timeout;
	rcu_read_unlock();
	dt = dt * HZ / 10;
	if (dt == 0)
		dt = MAX_SCHEDULE_TIMEOUT;

	dt = wait_event_timeout(device->misc_wait,
			*done ||
			test_bit(FORCE_DETACH, &device->flags) ||
			test_bit(ABORT_MDIO, &device->flags),
			dt);

	if (dt == 0) {
		drbd_err(device, "meta-data IO operation timed out\n");
		drbd_handle_io_error(device, DRBD_FORCE_DETACH);
	}
}

static int _drbd_md_sync_page_io(struct drbd_device *device,
				 struct drbd_backing_dev *bdev,
				 sector_t sector, enum req_op op)
{
	struct bio *bio;
	/* we do all our meta data IO in aligned 4k blocks. */
	const int size = 4096;
	int err;
	blk_opf_t op_flags = 0;

	if ((op == REQ_OP_WRITE) && !test_bit(MD_NO_FUA, &device->flags))
		op_flags |= REQ_FUA | REQ_PREFLUSH;
	op_flags |= REQ_META | REQ_SYNC;

	device->md_io.done = 0;
	device->md_io.error = -ENODEV;

	bio = bio_alloc_bioset(bdev->md_bdev, 1, op | op_flags,
		GFP_NOIO, &drbd_md_io_bio_set);
	bio->bi_iter.bi_sector = sector;
	err = -EIO;
	if (bio_add_page(bio, device->md_io.page, size, 0) != size)
		goto out;
	bio->bi_private = device;
	bio->bi_end_io = drbd_md_endio;

	if (op != REQ_OP_WRITE && device->disk_state[NOW] == D_DISKLESS && device->ldev == NULL)
		/* special case, drbd_md_read() during drbd_adm_attach(): no get_ldev */
		;
	else if (!get_ldev_if_state(device, D_ATTACHING)) {
		/* Corresponding put_ldev in drbd_md_endio() */
		drbd_err(device, "ASSERT FAILED: get_ldev_if_state() == 1 in _drbd_md_sync_page_io()\n");
		err = -ENODEV;
		goto out;
	}

	bio_get(bio); /* one bio_put() is in the completion handler */
	atomic_inc(&device->md_io.in_use); /* drbd_md_put_buffer() is in the completion handler */
	device->md_io.submit_jif = jiffies;
	if (drbd_insert_fault(device, (op == REQ_OP_WRITE) ? DRBD_FAULT_MD_WR : DRBD_FAULT_MD_RD)) {
		bio->bi_status = BLK_STS_IOERR;
		bio_endio(bio);
	} else {
		submit_bio(bio);
	}
	wait_until_done_or_force_detached(device, bdev, &device->md_io.done);
	err = device->md_io.error;
 out:
	bio_put(bio);
	return err;
}

int drbd_md_sync_page_io(struct drbd_device *device, struct drbd_backing_dev *bdev,
			 sector_t sector, enum req_op op)
{
	int err;
	D_ASSERT(device, atomic_read(&device->md_io.in_use) == 1);

	if (!bdev->md_bdev) {
		drbd_err_ratelimit(device, "bdev->md_bdev==NULL\n");
		return -EIO;
	}

	dynamic_drbd_dbg(device, "meta_data io: %s [%d]:%s(,%llus,%s) %pS\n",
	     current->comm, current->pid, __func__,
	     (unsigned long long)sector, (op == REQ_OP_WRITE) ? "WRITE" : "READ",
	     (void*)_RET_IP_ );

	if (sector < drbd_md_first_sector(bdev) ||
	    sector + 7 > drbd_md_last_sector(bdev))
		drbd_alert(device, "%s [%d]:%s(,%llus,%s) out of range md access!\n",
		     current->comm, current->pid, __func__,
		     (unsigned long long)sector,
		     (op == REQ_OP_WRITE) ? "WRITE" : "READ");

	err = _drbd_md_sync_page_io(device, bdev, sector, op);
	if (err) {
		drbd_err(device, "drbd_md_sync_page_io(,%llus,%s) failed with error %d\n",
		    (unsigned long long)sector,
		    (op == REQ_OP_WRITE) ? "WRITE" : "READ", err);
	}
	return err;
}

bool drbd_al_active(struct drbd_device *device, sector_t sector, unsigned int size)
{
	unsigned first = sector >> (AL_EXTENT_SHIFT-9);
	unsigned last = size == 0 ? first : (sector + (size >> 9) - 1) >> (AL_EXTENT_SHIFT-9);
	unsigned enr;
	bool active = false;

	spin_lock_irq(&device->al_lock);
	for (enr = first; enr <= last; enr++) {
		struct lc_element *al_ext;
		al_ext = lc_find(device->act_log, enr);
		if (al_ext && al_ext->refcnt > 0) {
			active = true;
			break;
		}
	}
	spin_unlock_irq(&device->al_lock);

	return active;
}

static
struct lc_element *_al_get_nonblock(struct drbd_device *device, unsigned int enr)
{
	struct lc_element *al_ext;

	spin_lock_irq(&device->al_lock);
	al_ext = lc_try_get(device->act_log, enr);
	spin_unlock_irq(&device->al_lock);

	return al_ext;
}

#if IS_ENABLED(CONFIG_DEV_DAX_PMEM) && !defined(DAX_PMEM_IS_INCOMPLETE)
static
struct lc_element *_al_get(struct drbd_device *device, unsigned int enr)
{
	struct lc_element *al_ext;

	spin_lock_irq(&device->al_lock);
	al_ext = lc_get(device->act_log, enr);
	spin_unlock_irq(&device->al_lock);

	return al_ext;
}

static bool
drbd_dax_begin_io_fp(struct drbd_device *device, unsigned int first, unsigned int last)
{
	struct lc_element *al_ext;
	unsigned long flags;
	unsigned int enr;
	unsigned int abort_enr;
	bool wake = 0;

	for (enr = first; enr <= last; enr++) {
		al_ext = _al_get(device, enr);
		if (!al_ext)
			goto abort;

		if (al_ext->lc_number != enr) {
			spin_lock_irqsave(&device->al_lock, flags);
			drbd_dax_al_update(device, al_ext);
			lc_committed(device->act_log);
			spin_unlock_irqrestore(&device->al_lock, flags);
		}
	}
	return true;
abort:
	abort_enr = enr;
	for (enr = first; enr < abort_enr; enr++) {
		spin_lock_irqsave(&device->al_lock, flags);
		al_ext = lc_find(device->act_log, enr);
		wake |= lc_put(device->act_log, al_ext) == 0;
		spin_unlock_irqrestore(&device->al_lock, flags);
	}
	if (wake)
		wake_up(&device->al_wait);
	return false;
}
#else
static bool
drbd_dax_begin_io_fp(struct drbd_device *device, unsigned int first, unsigned int last)
{
	return false;
}
#endif

bool drbd_al_begin_io_fastpath(struct drbd_device *device, struct drbd_interval *i)
{
	/* for bios crossing activity log extent boundaries,
	 * we may need to activate two extents in one go */
	unsigned first = i->sector >> (AL_EXTENT_SHIFT-9);
	unsigned last = i->size == 0 ? first : (i->sector + (i->size >> 9) - 1) >> (AL_EXTENT_SHIFT-9);

	D_ASSERT(device, first <= last);
	D_ASSERT(device, atomic_read(&device->local_cnt) > 0);

	if (drbd_md_dax_active(device->ldev))
		return drbd_dax_begin_io_fp(device, first, last);

	/* FIXME figure out a fast path for bios crossing AL extent boundaries */
	if (first != last)
		return false;

	return _al_get_nonblock(device, first) != NULL;
}

#if (PAGE_SHIFT + 3) < (AL_EXTENT_SHIFT - BM_BLOCK_SHIFT)
/* Currently BM_BLOCK_SHIFT and AL_EXTENT_SHIFT
 * are still coupled, or assume too much about their relation.
 * Code below will not work if this is violated.
 */
# error FIXME
#endif

static unsigned long al_extent_to_bm_bit(unsigned int al_enr)
{
	return (unsigned long)al_enr << (AL_EXTENT_SHIFT - BM_BLOCK_SHIFT);
}

static sector_t al_tr_number_to_on_disk_sector(struct drbd_device *device)
{
	const unsigned int stripes = device->ldev->md.al_stripes;
	const unsigned int stripe_size_4kB = device->ldev->md.al_stripe_size_4k;

	/* transaction number, modulo on-disk ring buffer wrap around */
	unsigned int t = device->al_tr_number % (device->ldev->md.al_size_4k);

	/* ... to aligned 4k on disk block */
	t = ((t % stripes) * stripe_size_4kB) + t/stripes;

	/* ... to 512 byte sector in activity log */
	t *= 8;

	/* ... plus offset to the on disk position */
	return device->ldev->md.md_offset + device->ldev->md.al_offset + t;
}

static int __al_write_transaction(struct drbd_device *device, struct al_transaction_on_disk *buffer)
{
	struct lc_element *e;
	sector_t sector;
	int i, mx;
	unsigned extent_nr;
	unsigned crc = 0;
	int err = 0;
	ktime_var_for_accounting(start_kt);

	memset(buffer, 0, sizeof(*buffer));
	buffer->magic = cpu_to_be32(DRBD_AL_MAGIC);
	buffer->tr_number = cpu_to_be32(device->al_tr_number);

	i = 0;

	drbd_bm_reset_al_hints(device);

	/* Even though no one can start to change this list
	 * once we set the LC_LOCKED -- from drbd_al_begin_io(),
	 * lc_try_lock_for_transaction() --, someone may still
	 * be in the process of changing it. */
	spin_lock_irq(&device->al_lock);
	list_for_each_entry(e, &device->act_log->to_be_changed, list) {
		if (i == AL_UPDATES_PER_TRANSACTION) {
			i++;
			break;
		}
		buffer->update_slot_nr[i] = cpu_to_be16(e->lc_index);
		buffer->update_extent_nr[i] = cpu_to_be32(e->lc_new_number);
		if (e->lc_number != LC_FREE) {
			unsigned long start, end;

			start = al_extent_to_bm_bit(e->lc_number);
			end = al_extent_to_bm_bit(e->lc_number + 1) - 1;
			drbd_bm_mark_range_for_writeout(device, start, end);
		}
		i++;
	}
	spin_unlock_irq(&device->al_lock);
	BUG_ON(i > AL_UPDATES_PER_TRANSACTION);

	buffer->n_updates = cpu_to_be16(i);
	for ( ; i < AL_UPDATES_PER_TRANSACTION; i++) {
		buffer->update_slot_nr[i] = cpu_to_be16(-1);
		buffer->update_extent_nr[i] = cpu_to_be32(LC_FREE);
	}

	buffer->context_size = cpu_to_be16(device->act_log->nr_elements);
	buffer->context_start_slot_nr = cpu_to_be16(device->al_tr_cycle);

	mx = min_t(int, AL_CONTEXT_PER_TRANSACTION,
		   device->act_log->nr_elements - device->al_tr_cycle);
	for (i = 0; i < mx; i++) {
		unsigned idx = device->al_tr_cycle + i;
		extent_nr = lc_element_by_index(device->act_log, idx)->lc_number;
		buffer->context[i] = cpu_to_be32(extent_nr);
	}
	for (; i < AL_CONTEXT_PER_TRANSACTION; i++)
		buffer->context[i] = cpu_to_be32(LC_FREE);

	device->al_tr_cycle += AL_CONTEXT_PER_TRANSACTION;
	if (device->al_tr_cycle >= device->act_log->nr_elements)
		device->al_tr_cycle = 0;

	sector = al_tr_number_to_on_disk_sector(device);

	crc = crc32c(0, buffer, 4096);
	buffer->crc32c = cpu_to_be32(crc);

	ktime_aggregate_delta(device, start_kt, al_before_bm_write_hinted_kt);
	err = drbd_bm_write_hinted(device);
	if (!err) {
		ktime_aggregate_delta(device, start_kt, al_mid_kt);
		if (drbd_md_sync_page_io(device, device->ldev, sector, REQ_OP_WRITE)) {
			err = -EIO;
			drbd_handle_io_error(device, DRBD_META_IO_ERROR);
		} else {
			device->al_tr_number++;
			device->al_writ_cnt++;
			device->al_histogram[min_t(unsigned int,
					device->act_log->pending_changes,
					AL_UPDATES_PER_TRANSACTION)]++;
		}
		ktime_aggregate_delta(device, start_kt, al_after_sync_page_kt);
	}

	return err;
}

static int al_write_transaction(struct drbd_device *device)
{
	struct al_transaction_on_disk *buffer;
	int err;

	if (!get_ldev(device)) {
		drbd_err(device, "disk is %s, cannot start al transaction\n",
			drbd_disk_str(device->disk_state[NOW]));
		return -EIO;
	}

	/* The bitmap write may have failed, causing a state change. */
	if (device->disk_state[NOW] < D_INCONSISTENT) {
		drbd_err(device,
			"disk is %s, cannot write al transaction\n",
			drbd_disk_str(device->disk_state[NOW]));
		put_ldev(device);
		return -EIO;
	}

	/* protects md_io_buffer, al_tr_cycle, ... */
	buffer = drbd_md_get_buffer(device, __func__);
	if (!buffer) {
		drbd_err(device, "disk failed while waiting for md_io buffer\n");
		put_ldev(device);
		return -ENODEV;
	}

	err = __al_write_transaction(device, buffer);

	drbd_md_put_buffer(device);
	put_ldev(device);

	return err;
}

bool drbd_al_try_lock(struct drbd_device *device)
{
	bool locked;

	spin_lock_irq(&device->al_lock);
	locked = lc_try_lock(device->act_log);
	spin_unlock_irq(&device->al_lock);

	return locked;
}

bool drbd_al_try_lock_for_transaction(struct drbd_device *device)
{
	bool locked;

	spin_lock_irq(&device->al_lock);
	locked = lc_try_lock_for_transaction(device->act_log);
	spin_unlock_irq(&device->al_lock);

	return locked;
}

void drbd_al_begin_io_commit(struct drbd_device *device)
{
	bool locked = false;


	if (drbd_md_dax_active(device->ldev)) {
		drbd_dax_al_begin_io_commit(device);
		return;
	}

	wait_event(device->al_wait,
			device->act_log->pending_changes == 0 ||
			(locked = drbd_al_try_lock_for_transaction(device)));

	if (locked) {
		/* Double check: it may have been committed by someone else
		 * while we were waiting for the lock. */
		if (device->act_log->pending_changes) {
			bool write_al_updates = !(device->ldev->md.flags & MDF_AL_DISABLED);

			if (write_al_updates)
				al_write_transaction(device);
			spin_lock_irq(&device->al_lock);
			/* FIXME
			if (err)
				we need an "lc_cancel" here;
			*/
			lc_committed(device->act_log);
			spin_unlock_irq(&device->al_lock);
		}
		lc_unlock(device->act_log);
		wake_up(&device->al_wait);
	}
}

static bool put_actlog(struct drbd_device *device, unsigned int first, unsigned int last)
{
	struct lc_element *extent;
	unsigned long flags;
	unsigned int enr;
	bool wake = false;

	D_ASSERT(device, first <= last);
	spin_lock_irqsave(&device->al_lock, flags);
	for (enr = first; enr <= last; enr++) {
		extent = lc_find(device->act_log, enr);
		/* Yes, this masks a bug elsewhere.  However, during normal
		 * operation this is harmless, so no need to crash the kernel
		 * by the BUG_ON(refcount == 0) in lc_put().
		 */
		if (!extent || extent->refcnt == 0) {
			drbd_err(device, "al_complete_io() called on inactive extent %u\n", enr);
			continue;
		}
		if (lc_put(device->act_log, extent) == 0)
			wake = true;
	}
	spin_unlock_irqrestore(&device->al_lock, flags);
	if (wake)
		wake_up(&device->al_wait);
	return wake;
}

int drbd_al_begin_io_nonblock(struct drbd_device *device, struct drbd_interval *i)
{
	/* for bios crossing activity log extent boundaries,
	 * we may need to activate two extents in one go */
	unsigned first = i->sector >> (AL_EXTENT_SHIFT-9);
	unsigned last = i->size == 0 ? first : (i->sector + (i->size >> 9) - 1) >> (AL_EXTENT_SHIFT-9);
	unsigned enr;

	if (i->partially_in_al_next_enr) {
		D_ASSERT(device, first < i->partially_in_al_next_enr);
		D_ASSERT(device, last >= i->partially_in_al_next_enr);
		first = i->partially_in_al_next_enr;
	}

	/* Try to checkout the refcounts. */
	for (enr = first; enr <= last; enr++) {
		struct lc_element *al_ext;
		al_ext = lc_get_cumulative(device->act_log, enr);

		if (!al_ext) {
			/* Did not work. We may have exhausted the possible
			 * changes per transaction. Or raced with someone
			 * "locking" it against changes.
			 * Remember where to continue from.
			 */
			if (enr > first)
				i->partially_in_al_next_enr = enr;
			return -ENOBUFS;
		}
	}
	return 0;
}

/* put activity log extent references corresponding to interval i, return true
 * if at least one extent is now unreferenced. */
bool drbd_al_complete_io(struct drbd_device *device, struct drbd_interval *i)
{
	/* for bios crossing activity log extent boundaries,
	 * we may need to activate two extents in one go */
	unsigned first = i->sector >> (AL_EXTENT_SHIFT-9);
	unsigned last = i->size == 0 ? first : (i->sector + (i->size >> 9) - 1) >> (AL_EXTENT_SHIFT-9);

	return put_actlog(device, first, last);
}

static int _try_lc_del(struct drbd_device *device, struct lc_element *al_ext)
{
	int rv;

	spin_lock_irq(&device->al_lock);
	rv = (al_ext->refcnt == 0);
	if (likely(rv))
		lc_del(device->act_log, al_ext);
	spin_unlock_irq(&device->al_lock);

	return rv;
}

/**
 * drbd_al_shrink() - Removes all active extents form the activity log
 * @device:	DRBD device.
 *
 * Removes all active extents form the activity log, waiting until
 * the reference count of each entry dropped to 0 first, of course.
 *
 * You need to lock device->act_log with lc_try_lock() / lc_unlock()
 */
void drbd_al_shrink(struct drbd_device *device)
{
	struct lc_element *al_ext;
	int i;

	D_ASSERT(device, test_bit(__LC_LOCKED, &device->act_log->flags));

	for (i = 0; i < device->act_log->nr_elements; i++) {
		al_ext = lc_element_by_index(device->act_log, i);
		if (al_ext->lc_number == LC_FREE)
			continue;
		wait_event(device->al_wait, _try_lc_del(device, al_ext));
	}

	wake_up(&device->al_wait);
}

int drbd_al_initialize(struct drbd_device *device, void *buffer)
{
	struct al_transaction_on_disk *al = buffer;
	struct drbd_md *md = &device->ldev->md;
	int al_size_4k = md->al_stripes * md->al_stripe_size_4k;
	int i;

	if (drbd_md_dax_active(device->ldev))
		return drbd_dax_al_initialize(device);

	__al_write_transaction(device, al);
	/* There may or may not have been a pending transaction. */
	spin_lock_irq(&device->al_lock);
	lc_committed(device->act_log);
	spin_unlock_irq(&device->al_lock);

	/* The rest of the transactions will have an empty "updates" list, and
	 * are written out only to provide the context, and to initialize the
	 * on-disk ring buffer. */
	for (i = 1; i < al_size_4k; i++) {
		int err = __al_write_transaction(device, al);
		if (err)
			return err;
	}
	return 0;
}

void drbd_advance_rs_marks(struct drbd_peer_device *peer_device, unsigned long still_to_go)
{
	unsigned long now;
	int next;

	/* report progress and advance marks only if we made progress */
	if (peer_device->rs_mark_left[peer_device->rs_last_mark] == still_to_go)
		return;

	/* report progress and advance marks at most once every DRBD_SYNC_MARK_STEP (3 seconds) */
	now = jiffies;
	if (!time_after_eq(now, peer_device->rs_last_progress_report_ts + DRBD_SYNC_MARK_STEP))
		return;

	/* Do not advance marks if we are "paused" */
	if (peer_device->repl_state[NOW] != L_PAUSED_SYNC_T &&
	    peer_device->repl_state[NOW] != L_PAUSED_SYNC_S) {
		next = (peer_device->rs_last_mark + 1) % DRBD_SYNC_MARKS;
		peer_device->rs_mark_time[next] = now;
		peer_device->rs_mark_left[next] = still_to_go;
		peer_device->rs_last_mark = next;
	}

	/* But still report progress even if paused. */
	peer_device->rs_last_progress_report_ts = now;
	drbd_peer_device_post_work(peer_device, RS_PROGRESS);
}

/* It is called lazy update, so don't do write-out too often. */
bool drbd_lazy_bitmap_update_due(struct drbd_peer_device *peer_device)
{
	return time_after(jiffies, peer_device->rs_last_writeout + 2*HZ);
}

void drbd_check_resync_done(struct drbd_peer_device *peer_device)
{
	struct drbd_device *device = peer_device->device;
	bool is_sync_target;
	unsigned long still_to_go;

	is_sync_target = is_sync_target_state(peer_device, NOW);

	/* Evaluate is_sync_target_state before getting the bm
	 * total weight. We only want to finish a sync if we
	 * were in a sync target state and then clear the last
	 * bits.
	 *
	 * Use an explicit read barrier to ensure that the
	 * state is read before the bitmap is checked. The
	 * corresponding release is implied when the bitmap is
	 * unlocked after it is received.
	 */
	smp_rmb();
	still_to_go = drbd_bm_total_weight(peer_device);
	drbd_advance_rs_marks(peer_device, still_to_go);

	if (peer_device->connection->agreed_pro_version > 95 && !is_sync_target) {
		/* If sync source: rather wait for explicit notification via
		 * receive_state, to avoid uuids-rotated-too-fast causing full
		 * resync in next handshake, in case the replication link
		 * breaks at the most unfortunate time... */

		return;
	}

	if (still_to_go <= peer_device->rs_failed &&
			!drbd_any_flush_pending(device->resource))
		drbd_peer_device_post_work(peer_device, RS_DONE);
}


static int update_sync_bits(struct drbd_peer_device *peer_device,
		unsigned long sbnr, unsigned long ebnr,
		enum update_sync_bits_mode mode)
{
	struct drbd_device *device = peer_device->device;
	unsigned long count = 0;
	int bmi = peer_device->bitmap_index;

	if (mode == RECORD_RS_FAILED)
		/* Only called from drbd_rs_failed_io(), bits
		 * supposedly still set.  Recount, maybe some
		 * of the bits have been successfully cleared
		 * by application IO meanwhile.
		 */
		count = drbd_bm_count_bits(device, bmi, sbnr, ebnr);
	else if (mode == SET_IN_SYNC)
		count = drbd_bm_clear_bits(device, bmi, sbnr, ebnr);
	else /* if (mode == SET_OUT_OF_SYNC) */
		count = drbd_bm_set_bits(device, bmi, sbnr, ebnr);

	if (count) {
		if (mode == SET_IN_SYNC) {
			if (drbd_lazy_bitmap_update_due(peer_device))
				drbd_peer_device_post_work(peer_device, RS_LAZY_BM_WRITE);

			drbd_check_resync_done(peer_device);
		} else if (mode == RECORD_RS_FAILED) {
			peer_device->rs_failed += count;
		} else /* if (mode == SET_OUT_OF_SYNC) */ {
			enum drbd_repl_state repl_state = peer_device->repl_state[NOW];
			if (repl_state >= L_SYNC_SOURCE && repl_state <= L_PAUSED_SYNC_T)
				peer_device->rs_total += count;
		}
		wake_up(&device->al_wait);
	}
	return count;
}

/* clear the bit corresponding to the piece of storage in question:
 * size byte of data starting from sector.  Only clear a bits of the affected
 * one or more _aligned_ BM_BLOCK_SIZE blocks.
 *
 * called by worker on L_SYNC_TARGET and receiver on SyncSource.
 *
 */
int __drbd_change_sync(struct drbd_peer_device *peer_device, sector_t sector, int size,
		enum update_sync_bits_mode mode)
{
	/* Is called from worker and receiver context _only_ */
	struct drbd_device *device = peer_device->device;
	unsigned long sbnr, ebnr, lbnr;
	unsigned long count = 0;
	sector_t esector, nr_sectors;

	/* This would be an empty REQ_OP_FLUSH, be silent. */
	if ((mode == SET_OUT_OF_SYNC) && size == 0)
		return 0;

	if (peer_device->bitmap_index == -1) /* no bitmap... */
		return 0;

	if (!get_ldev(device))
		return 0; /* no disk, no metadata, no bitmap to manipulate bits in */

	nr_sectors = get_capacity(device->vdisk);
	esector = sector + (size >> 9) - 1;

	if (!expect(peer_device, sector < nr_sectors))
		goto out;
	if (!expect(peer_device, esector < nr_sectors))
		esector = nr_sectors - 1;

	lbnr = BM_SECT_TO_BIT(nr_sectors-1);

	if (mode == SET_IN_SYNC) {
		/* Round up start sector, round down end sector.  We make sure
		 * we only clear full, aligned, BM_BLOCK_SIZE blocks. */
		if (unlikely(esector < BM_SECT_PER_BIT-1))
			goto out;
		if (unlikely(esector == (nr_sectors-1)))
			ebnr = lbnr;
		else
			ebnr = BM_SECT_TO_BIT(esector - (BM_SECT_PER_BIT-1));
		sbnr = BM_SECT_TO_BIT(sector + BM_SECT_PER_BIT-1);
	} else {
		/* We set it out of sync, or record resync failure.
		 * Should not round anything here. */
		sbnr = BM_SECT_TO_BIT(sector);
		ebnr = BM_SECT_TO_BIT(esector);
	}

	count = update_sync_bits(peer_device, sbnr, ebnr, mode);
out:
	put_ldev(device);
	return count;
}

int drbd_set_all_out_of_sync(struct drbd_device *device, sector_t sector, int size)
{
	return drbd_set_sync(device, sector, size, -1, -1);
}

/**
 * drbd_set_sync  -  Set a disk range in or out of sync
 * @device:	DRBD device
 * @sector:	start sector of disk range
 * @size:	size of disk range in bytes
 * @bits:	bit values to use by bitmap index
 * @mask:	bitmap indexes to modify (mask set)
 *
 * Returns the number of bits modified.
 */
int drbd_set_sync(struct drbd_device *device, sector_t sector, int size,
		   unsigned long bits, unsigned long mask)
{
	long set_start, set_end, clear_start, clear_end;
	struct drbd_peer_device *peer_device;
	sector_t esector, nr_sectors;
	unsigned long irq_flags;
	int count = 0;

	mask &= (1 << device->bitmap->bm_max_peers) - 1;

	if (size <= 0 || !IS_ALIGNED(size, 512)) {
		drbd_err(device, "%s sector: %llus, size: %d\n",
			 __func__, (unsigned long long)sector, size);
		return false;
	}

	if (!get_ldev(device))
		return false; /* no disk, no metadata, no bitmap to set bits in */

	nr_sectors = get_capacity(device->vdisk);
	esector = sector + (size >> 9) - 1;

	if (!expect(device, sector < nr_sectors))
		goto out;
	if (!expect(device, esector < nr_sectors))
		esector = nr_sectors - 1;

	/* For marking sectors as out of sync, we need to round up. */
	set_start = BM_SECT_TO_BIT(sector);
	set_end = BM_SECT_TO_BIT(esector);

	/* For marking sectors as in sync, we need to round down except when we
	 * reach the end of the device: The last bit in the bitmap does not
	 * account for sectors past the end of the device.
	 * CLEAR_END can become negative here. */
	clear_start = BM_SECT_TO_BIT(sector + BM_SECT_PER_BIT - 1);
	if (esector == nr_sectors - 1)
		clear_end = BM_SECT_TO_BIT(esector);
	else
		clear_end = BM_SECT_TO_BIT(esector + 1) - 1;

	spin_lock_irqsave(&device->bitmap->bm_all_slots_lock, irq_flags);
	rcu_read_lock();
	for_each_peer_device_rcu(peer_device, device) {
		int bitmap_index = peer_device->bitmap_index;

		if (bitmap_index == -1)
			continue;

		if (!test_and_clear_bit(bitmap_index, &mask))
			continue;

		if (test_bit(bitmap_index, &bits))
			count += update_sync_bits(peer_device, set_start, set_end, SET_OUT_OF_SYNC);

		else if (clear_start <= clear_end)
			count += update_sync_bits(peer_device, clear_start, clear_end, SET_IN_SYNC);
	}
	rcu_read_unlock();
	if (mask) {
		int bitmap_index;

		for_each_set_bit(bitmap_index, &mask, BITS_PER_LONG) {
			if (test_bit(bitmap_index, &bits))
				count += drbd_bm_set_bits(device, bitmap_index,
						 set_start, set_end);
			else if (clear_start <= clear_end)
				count += drbd_bm_clear_bits(device, bitmap_index,
						   clear_start, clear_end);
		}
	}
	spin_unlock_irqrestore(&device->bitmap->bm_all_slots_lock, irq_flags);
out:
	put_ldev(device);

	return count;
}
