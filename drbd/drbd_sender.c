/*
   drbd_sender.c

   This file is part of DRBD by Philipp Reisner and Lars Ellenberg.

   Copyright (C) 2001-2008, LINBIT Information Technologies GmbH.
   Copyright (C) 1999-2008, Philipp Reisner <philipp.reisner@linbit.com>.
   Copyright (C) 2002-2008, Lars Ellenberg <lars.ellenberg@linbit.com>.

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

#include <linux/autoconf.h>
#include <linux/module.h>
#include <linux/drbd.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/mm.h>
#include <linux/memcontrol.h>
#include <linux/mm_inline.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/scatterlist.h>

#include "drbd_int.h"
#include "drbd_protocol.h"
#include "drbd_req.h"

static int make_ov_request(struct drbd_peer_device *, int);
static int make_resync_request(struct drbd_peer_device *, int);

/* endio handlers:
 *   drbd_md_io_complete (defined here)
 *   drbd_request_endio (defined here)
 *   drbd_peer_request_endio (defined here)
 *   bm_async_io_complete (defined in drbd_bitmap.c)
 *
 * For all these callbacks, note the following:
 * The callbacks will be called in irq context by the IDE drivers,
 * and in Softirqs/Tasklets/BH context by the SCSI drivers.
 * Try to get the locking right :)
 *
 */

struct mutex global_state_mutex;

/* used for synchronous meta data and bitmap IO
 * submitted by drbd_md_sync_page_io()
 */
BIO_ENDIO_TYPE drbd_md_io_complete BIO_ENDIO_ARGS(struct bio *bio, int error)
{
	struct drbd_md_io *md_io;
	struct drbd_device *device;

	BIO_ENDIO_FN_START;

	md_io = (struct drbd_md_io *)bio->bi_private;
	device = container_of(md_io, struct drbd_device, md_io);

	md_io->error = error;

	/* We grabbed an extra reference in _drbd_md_sync_page_io() to be able
	 * to timeout on the lower level device, and eventually detach from it.
	 * If this io completion runs after that timeout expired, this
	 * drbd_md_put_buffer() may allow us to finally try and re-attach.
	 * During normal operation, this only puts that extra reference
	 * down to 1 again.
	 * Make sure we first drop the reference, and only then signal
	 * completion, or we may (in drbd_al_read_log()) cycle so fast into the
	 * next drbd_md_sync_page_io(), that we trigger the
	 * ASSERT(atomic_read(&mdev->md_io_in_use) == 1) there.
	 */
	drbd_md_put_buffer(device);
	md_io->done = 1;
	wake_up(&device->misc_wait);
	bio_put(bio);
	put_ldev(device);

	BIO_ENDIO_FN_RETURN;
}

/* reads on behalf of the partner,
 * "submitted" by the receiver
 */
void drbd_endio_read_sec_final(struct drbd_peer_request *peer_req) __releases(local)
{
	unsigned long flags = 0;
	struct drbd_peer_device *peer_device = peer_req->peer_device;
	struct drbd_device *device = peer_device->device;

	spin_lock_irqsave(&device->resource->req_lock, flags);
	device->read_cnt += peer_req->i.size >> 9;
	list_del(&peer_req->w.list);
	if (list_empty(&device->read_ee))
		wake_up(&device->ee_wait);
	if (test_bit(__EE_WAS_ERROR, &peer_req->flags))
		__drbd_chk_io_error(device, false);
	spin_unlock_irqrestore(&device->resource->req_lock, flags);

	drbd_queue_work(&peer_device->connection->sender_work, &peer_req->w);
	put_ldev(device);
}

static int is_failed_barrier(int ee_flags)
{
	return (ee_flags & (EE_IS_BARRIER|EE_WAS_ERROR|EE_RESUBMITTED))
		== (EE_IS_BARRIER|EE_WAS_ERROR);
}

/* writes on behalf of the partner, or resync writes,
 * "submitted" by the receiver, final stage.  */
static void drbd_endio_write_sec_final(struct drbd_peer_request *peer_req) __releases(local)
{
	unsigned long flags = 0;
	struct drbd_peer_device *peer_device = peer_req->peer_device;
	struct drbd_device *device = peer_device->device;
	struct drbd_interval i;
	int do_wake;
	u64 block_id;
	int do_al_complete_io;

	/* if this is a failed barrier request, disable use of barriers,
	 * and schedule for resubmission */
	if (is_failed_barrier(peer_req->flags)) {
		drbd_bump_write_ordering(device->resource, WO_BDEV_FLUSH);
		spin_lock_irqsave(&device->resource->req_lock, flags);
		list_del(&peer_req->w.list);
		peer_req->flags = (peer_req->flags & ~EE_WAS_ERROR) | EE_RESUBMITTED;
		peer_req->w.cb = w_e_reissue;
		/* put_ldev actually happens below, once we come here again. */
		__release(local);
		spin_unlock_irqrestore(&device->resource->req_lock, flags);
		drbd_queue_work(&peer_device->connection->sender_work, &peer_req->w);
		return;
	}

	/* after we moved peer_req to done_ee,
	 * we may no longer access it,
	 * it may be freed/reused already!
	 * (as soon as we release the req_lock) */
	i = peer_req->i;
	do_al_complete_io = peer_req->flags & EE_CALL_AL_COMPLETE_IO;
	block_id = peer_req->block_id;

	spin_lock_irqsave(&device->resource->req_lock, flags);
	device->writ_cnt += peer_req->i.size >> 9;
	list_del(&peer_req->w.list); /* has been on active_ee or sync_ee */
	list_add_tail(&peer_req->w.list, &device->done_ee);

	/*
	 * Do not remove from the write_requests tree here: we did not send the
	 * Ack yet and did not wake possibly waiting conflicting requests.
	 * Removed from the tree from "drbd_process_done_ee" within the
	 * appropriate callback (e_end_block/e_end_resync_block) or from
	 * _drbd_clear_done_ee.
	 */

	do_wake = list_empty(block_id == ID_SYNCER ? &device->sync_ee : &device->active_ee);

	if (test_bit(__EE_WAS_ERROR, &peer_req->flags))
		__drbd_chk_io_error(device, false);
	spin_unlock_irqrestore(&device->resource->req_lock, flags);

	if (block_id == ID_SYNCER)
		drbd_rs_complete_io(peer_device, i.sector);

	if (do_wake)
		wake_up(&device->ee_wait);

	if (do_al_complete_io)
		drbd_al_complete_io(device, &i);

	wake_asender(peer_device->connection);
	put_ldev(device);
}

/* writes on behalf of the partner, or resync writes,
 * "submitted" by the receiver.
 */
BIO_ENDIO_TYPE drbd_peer_request_endio BIO_ENDIO_ARGS(struct bio *bio, int error)
{
	struct drbd_peer_request *peer_req = bio->bi_private;
	struct drbd_device *device = peer_req->peer_device->device;
	int uptodate = bio_flagged(bio, BIO_UPTODATE);
	int is_write = bio_data_dir(bio) == WRITE;

	BIO_ENDIO_FN_START;
	if (error && drbd_ratelimit())
		drbd_warn(device, "%s: error=%d s=%llus\n",
				is_write ? "write" : "read", error,
				(unsigned long long)peer_req->i.sector);
	if (!error && !uptodate) {
		if (drbd_ratelimit())
			drbd_warn(device, "%s: setting error to -EIO s=%llus\n",
					is_write ? "write" : "read",
					(unsigned long long)peer_req->i.sector);
		/* strange behavior of some lower level drivers...
		 * fail the request by clearing the uptodate flag,
		 * but do not return any error?! */
		error = -EIO;
	}

	if (error)
		set_bit(__EE_WAS_ERROR, &peer_req->flags);

	bio_put(bio); /* no need for the bio anymore */
	if (atomic_dec_and_test(&peer_req->pending_bios)) {
		if (is_write)
			drbd_endio_write_sec_final(peer_req);
		else
			drbd_endio_read_sec_final(peer_req);
	}
	BIO_ENDIO_FN_RETURN;
}

/* read, readA or write requests on R_PRIMARY coming from drbd_make_request
 */
BIO_ENDIO_TYPE drbd_request_endio BIO_ENDIO_ARGS(struct bio *bio, int error)
{
	unsigned long flags;
	struct drbd_request *req = bio->bi_private;
	struct drbd_device *device = req->device;
	struct bio_and_error m;
	enum drbd_req_event what;
	int uptodate = bio_flagged(bio, BIO_UPTODATE);

	BIO_ENDIO_FN_START;
	if (!error && !uptodate) {
		drbd_warn(device, "p %s: setting error to -EIO\n",
			 bio_data_dir(bio) == WRITE ? "write" : "read");
		/* strange behavior of some lower level drivers...
		 * fail the request by clearing the uptodate flag,
		 * but do not return any error?! */
		error = -EIO;
	}

	/* to avoid recursion in __req_mod */
	if (unlikely(error)) {
		what = (bio_data_dir(bio) == WRITE)
			? WRITE_COMPLETED_WITH_ERROR
			: (bio_rw(bio) == READ)
			  ? READ_COMPLETED_WITH_ERROR
			  : READ_AHEAD_COMPLETED_WITH_ERROR;
	} else
		what = COMPLETED_OK;

	bio_put(req->private_bio);
	req->private_bio = ERR_PTR(error);

	/* not req_mod(), we need irqsave here! */
	spin_lock_irqsave(&device->resource->req_lock, flags);
	__req_mod(req, what, &m);
	spin_unlock_irqrestore(&device->resource->req_lock, flags);
	put_ldev(device);

	if (m.bio)
		complete_master_bio(device, &m);
	BIO_ENDIO_FN_RETURN;
}

void drbd_csum_ee(struct crypto_hash *tfm, struct drbd_peer_request *peer_req, void *digest)
{
	struct hash_desc desc;
	struct scatterlist sg;
	struct page *page = peer_req->pages;
	struct page *tmp;
	unsigned len;

	desc.tfm = tfm;
	desc.flags = 0;

	sg_init_table(&sg, 1);
	crypto_hash_init(&desc);

	while ((tmp = page_chain_next(page))) {
		/* all but the last page will be fully used */
		sg_set_page(&sg, page, PAGE_SIZE, 0);
		crypto_hash_update(&desc, &sg, sg.length);
		page = tmp;
	}
	/* and now the last, possibly only partially used page */
	len = peer_req->i.size & (PAGE_SIZE - 1);
	sg_set_page(&sg, page, len ?: PAGE_SIZE, 0);
	crypto_hash_update(&desc, &sg, sg.length);
	crypto_hash_final(&desc, digest);
}

void drbd_csum_bio(struct crypto_hash *tfm, struct bio *bio, void *digest)
{
	struct hash_desc desc;
	struct scatterlist sg;
	struct bio_vec *bvec;
	int i;

	desc.tfm = tfm;
	desc.flags = 0;

	sg_init_table(&sg, 1);
	crypto_hash_init(&desc);

	bio_for_each_segment(bvec, bio, i) {
		sg_set_page(&sg, bvec->bv_page, bvec->bv_len, bvec->bv_offset);
		crypto_hash_update(&desc, &sg, sg.length);
	}
	crypto_hash_final(&desc, digest);
}

/* MAYBE merge common code with w_e_end_ov_req */
STATIC int w_e_send_csum(struct drbd_work *w, int cancel)
{
	struct drbd_peer_request *peer_req = container_of(w, struct drbd_peer_request, w);
	struct drbd_peer_device *peer_device = peer_req->peer_device;
	struct drbd_device *device = peer_device->device;
	int digest_size;
	void *digest;
	int err = 0;

	if (unlikely(cancel))
		goto out;

	if (unlikely((peer_req->flags & EE_WAS_ERROR) != 0))
		goto out;

	digest_size = crypto_hash_digestsize(peer_device->connection->csums_tfm);
	digest = kmalloc(digest_size, GFP_NOIO);
	if (digest) {
		sector_t sector = peer_req->i.sector;
		unsigned int size = peer_req->i.size;
		drbd_csum_ee(peer_device->connection->csums_tfm, peer_req, digest);
		/* Free peer_req and pages before send.
		 * In case we block on congestion, we could otherwise run into
		 * some distributed deadlock, if the other side blocks on
		 * congestion as well, because our receiver blocks in
		 * drbd_alloc_pages due to pp_in_use > max_buffers. */
		drbd_free_peer_req(device, peer_req);
		peer_req = NULL;
		inc_rs_pending(peer_device);
		err = drbd_send_drequest_csum(peer_device, sector, size,
					      digest, digest_size,
					      P_CSUM_RS_REQUEST);
		kfree(digest);
	} else {
		drbd_err(device, "kmalloc() of digest failed.\n");
		err = -ENOMEM;
	}

out:
	if (peer_req)
		drbd_free_peer_req(device, peer_req);

	if (unlikely(err))
		drbd_err(device, "drbd_send_drequest(..., csum) failed\n");
	return err;
}

#define GFP_TRY	(__GFP_HIGHMEM | __GFP_NOWARN)

static int read_for_csum(struct drbd_peer_device *peer_device, sector_t sector, int size)
{
	struct drbd_device *device = peer_device->device;
	struct drbd_peer_request *peer_req;

	if (!get_ldev(device))
		return -EIO;

	if (drbd_rs_should_slow_down(peer_device, sector))
		goto defer;

	/* GFP_TRY, because if there is no memory available right now, this may
	 * be rescheduled for later. It is "only" background resync, after all. */
	peer_req = drbd_alloc_peer_req(peer_device, ID_SYNCER /* unused */, sector,
				       size, GFP_TRY);
	if (!peer_req)
		goto defer;

	peer_req->w.cb = w_e_send_csum;
	spin_lock_irq(&device->resource->req_lock);
	list_add(&peer_req->w.list, &device->read_ee);
	spin_unlock_irq(&device->resource->req_lock);

	atomic_add(size >> 9, &device->rs_sect_ev);
	if (drbd_submit_peer_request(device, peer_req, READ, DRBD_FAULT_RS_RD) == 0)
		return 0;

	/* If it failed because of ENOMEM, retry should help.  If it failed
	 * because bio_add_page failed (probably broken lower level driver),
	 * retry may or may not help.
	 * If it does not, you may need to force disconnect. */
	spin_lock_irq(&device->resource->req_lock);
	list_del(&peer_req->w.list);
	spin_unlock_irq(&device->resource->req_lock);

	drbd_free_peer_req(device, peer_req);
defer:
	put_ldev(device);
	return -EAGAIN;
}

int w_resync_timer(struct drbd_work *w, int cancel)
{
	struct drbd_peer_device *peer_device =
		container_of(w, struct drbd_peer_device, resync_work);

	switch (peer_device->repl_state[NOW]) {
	case L_VERIFY_S:
		make_ov_request(peer_device, cancel);
		break;
	case L_SYNC_TARGET:
		make_resync_request(peer_device, cancel);
		break;
	default:
		break;
	}

	return 0;
}

void resync_timer_fn(unsigned long data)
{
	struct drbd_peer_device *peer_device = (struct drbd_peer_device *) data;

	if (list_empty(&peer_device->resync_work.list))
		drbd_queue_work(&peer_device->connection->sender_work,
				&peer_device->resync_work);
}

static void fifo_set(struct fifo_buffer *fb, int value)
{
	int i;

	for (i = 0; i < fb->size; i++)
		fb->values[i] = value;
}

static int fifo_push(struct fifo_buffer *fb, int value)
{
	int ov;

	ov = fb->values[fb->head_index];
	fb->values[fb->head_index++] = value;

	if (fb->head_index >= fb->size)
		fb->head_index = 0;

	return ov;
}

static void fifo_add_val(struct fifo_buffer *fb, int value)
{
	int i;

	for (i = 0; i < fb->size; i++)
		fb->values[i] += value;
}

struct fifo_buffer *fifo_alloc(int fifo_size)
{
	struct fifo_buffer *fb;

	fb = kzalloc(sizeof(struct fifo_buffer) + sizeof(int) * fifo_size, GFP_KERNEL);
	if (!fb)
		return NULL;

	fb->head_index = 0;
	fb->size = fifo_size;
	fb->total = 0;

	return fb;
}

STATIC int drbd_rs_controller(struct drbd_peer_device *peer_device)
{
	struct drbd_device *device = peer_device->device;
	struct disk_conf *dc;
	unsigned int sect_in;  /* Number of sectors that came in since the last turn */
	unsigned int want;     /* The number of sectors we want in the proxy */
	int req_sect; /* Number of sectors to request in this turn */
	int correction; /* Number of sectors more we need in the proxy*/
	int cps; /* correction per invocation of drbd_rs_controller() */
	int steps; /* Number of time steps to plan ahead */
	int curr_corr;
	int max_sect;
	struct fifo_buffer *plan;

	sect_in = atomic_xchg(&peer_device->rs_sect_in, 0); /* Number of sectors that came in */
	peer_device->rs_in_flight -= sect_in;

	dc = rcu_dereference(device->ldev->disk_conf);
	plan = rcu_dereference(peer_device->rs_plan_s);

	steps = plan->size; /* (dc->c_plan_ahead * 10 * SLEEP_TIME) / HZ; */

	if (peer_device->rs_in_flight + sect_in == 0) { /* At start of resync */
		want = ((dc->resync_rate * 2 * SLEEP_TIME) / HZ) * steps;
	} else { /* normal path */
		want = dc->c_fill_target ? dc->c_fill_target :
			sect_in * dc->c_delay_target * HZ / (SLEEP_TIME * 10);
	}

	correction = want - peer_device->rs_in_flight - plan->total;

	/* Plan ahead */
	cps = correction / steps;
	fifo_add_val(plan, cps);
	plan->total += cps * steps;

	/* What we do in this step */
	curr_corr = fifo_push(plan, 0);
	plan->total -= curr_corr;

	req_sect = sect_in + curr_corr;
	if (req_sect < 0)
		req_sect = 0;

	max_sect = (dc->c_max_rate * 2 * SLEEP_TIME) / HZ;
	if (req_sect > max_sect)
		req_sect = max_sect;

	/*
	drbd_warn(device, "si=%u if=%d wa=%u co=%d st=%d cps=%d pl=%d cc=%d rs=%d\n",
		 sect_in, peer_device->rs_in_flight, want, correction,
		 steps, cps, peer_device->rs_planed, curr_corr, req_sect);
	*/

	return req_sect;
}

STATIC int drbd_rs_number_requests(struct drbd_peer_device *peer_device)
{
	struct drbd_device *device = peer_device->device;
	int number;

	rcu_read_lock();
	if (rcu_dereference(peer_device->rs_plan_s)->size) {
		number = drbd_rs_controller(peer_device) >> (BM_BLOCK_SHIFT - 9);
		peer_device->c_sync_rate = number * HZ * (BM_BLOCK_SIZE / 1024) / SLEEP_TIME;
	} else {
		peer_device->c_sync_rate = rcu_dereference(device->ldev->disk_conf)->resync_rate;
		number = SLEEP_TIME * peer_device->c_sync_rate  / ((BM_BLOCK_SIZE / 1024) * HZ);
	}
	rcu_read_unlock();

	/* ignore the amount of pending requests, the resync controller should
	 * throttle down to incoming reply rate soon enough anyways. */
	return number;
}

static int make_resync_request(struct drbd_peer_device *peer_device, int cancel)
{
	struct drbd_device *device = peer_device->device;
	unsigned long bit;
	sector_t sector;
	const sector_t capacity = drbd_get_capacity(device->this_bdev);
	int max_bio_size;
	int number, rollback_i, size;
	int align, queued, sndbuf;
	int i = 0;

	if (unlikely(cancel))
		return 0;

	if (peer_device->rs_total == 0) {
		/* empty resync? */
		drbd_resync_finished(peer_device);
		return 0;
	}

	if (!get_ldev(device)) {
		/* Since we only need to access device->rsync a
		   get_ldev_if_state(device,D_FAILED) would be sufficient, but
		   to continue resync with a broken disk makes no sense at
		   all */
		drbd_err(device, "Disk broke down during resync!\n");
		return 0;
	}

	max_bio_size = queue_max_hw_sectors(device->rq_queue) << 9;
	number = drbd_rs_number_requests(peer_device);
	if (number == 0)
		goto requeue;

	for (i = 0; i < number; i++) {
		/* Stop generating RS requests, when half of the send buffer is filled */
		mutex_lock(&peer_device->connection->data.mutex);
		if (peer_device->connection->data.socket) {
			queued = peer_device->connection->data.socket->sk->sk_wmem_queued;
			sndbuf = peer_device->connection->data.socket->sk->sk_sndbuf;
		} else {
			queued = 1;
			sndbuf = 0;
		}
		mutex_unlock(&peer_device->connection->data.mutex);
		if (queued > sndbuf / 2)
			goto requeue;

next_sector:
		size = BM_BLOCK_SIZE;
		bit  = drbd_bm_find_next(peer_device, device->bm_resync_fo);

		if (bit == DRBD_END_OF_BITMAP) {
			device->bm_resync_fo = drbd_bm_bits(device);
			put_ldev(device);
			return 0;
		}

		sector = BM_BIT_TO_SECT(bit);

		if (drbd_rs_should_slow_down(peer_device, sector) ||
		    drbd_try_rs_begin_io(peer_device, sector)) {
			device->bm_resync_fo = bit;
			goto requeue;
		}
		device->bm_resync_fo = bit + 1;

		if (unlikely(drbd_bm_test_bit(peer_device, bit) == 0)) {
			drbd_rs_complete_io(peer_device, sector);
			goto next_sector;
		}

#if DRBD_MAX_BIO_SIZE > BM_BLOCK_SIZE
		/* try to find some adjacent bits.
		 * we stop if we have already the maximum req size.
		 *
		 * Additionally always align bigger requests, in order to
		 * be prepared for all stripe sizes of software RAIDs.
		 */
		align = 1;
		rollback_i = i;
		for (;;) {
			if (size + BM_BLOCK_SIZE > max_bio_size)
				break;

			/* Be always aligned */
			if (sector & ((1<<(align+3))-1))
				break;

			/* do not cross extent boundaries */
			if (((bit+1) & BM_BLOCKS_PER_BM_EXT_MASK) == 0)
				break;
			/* now, is it actually dirty, after all?
			 * caution, drbd_bm_test_bit is tri-state for some
			 * obscure reason; ( b == 0 ) would get the out-of-band
			 * only accidentally right because of the "oddly sized"
			 * adjustment below */
			if (drbd_bm_test_bit(peer_device, bit + 1) != 1)
				break;
			bit++;
			size += BM_BLOCK_SIZE;
			if ((BM_BLOCK_SIZE << align) <= size)
				align++;
			i++;
		}
		/* if we merged some,
		 * reset the offset to start the next drbd_bm_find_next from */
		if (size > BM_BLOCK_SIZE)
			device->bm_resync_fo = bit + 1;
#endif

		/* adjust very last sectors, in case we are oddly sized */
		if (sector + (size>>9) > capacity)
			size = (capacity-sector)<<9;
		if (peer_device->connection->agreed_pro_version >= 89 &&
		    peer_device->connection->csums_tfm) {
			switch (read_for_csum(peer_device, sector, size)) {
			case -EIO: /* Disk failure */
				put_ldev(device);
				return -EIO;
			case -EAGAIN: /* allocation failed, or ldev busy */
				drbd_rs_complete_io(peer_device, sector);
				device->bm_resync_fo = BM_SECT_TO_BIT(sector);
				i = rollback_i;
				goto requeue;
			case 0:
				/* everything ok */
				break;
			default:
				BUG();
			}
		} else {
			int err;

			inc_rs_pending(peer_device);
			err = drbd_send_drequest(peer_device, P_RS_DATA_REQUEST,
						 sector, size, ID_SYNCER);
			if (err) {
				drbd_err(device, "drbd_send_drequest() failed, aborting...\n");
				dec_rs_pending(peer_device);
				put_ldev(device);
				return err;
			}
		}
	}

	if (device->bm_resync_fo >= drbd_bm_bits(device)) {
		/* last syncer _request_ was sent,
		 * but the P_RS_DATA_REPLY not yet received.  sync will end (and
		 * next sync group will resume), as soon as we receive the last
		 * resync data block, and the last bit is cleared.
		 * until then resync "work" is "inactive" ...
		 */
		put_ldev(device);
		return 0;
	}

 requeue:
	peer_device->rs_in_flight += (i << (BM_BLOCK_SHIFT - 9));
	mod_timer(&peer_device->resync_timer, jiffies + SLEEP_TIME);
	put_ldev(device);
	return 0;
}

static int make_ov_request(struct drbd_peer_device *peer_device, int cancel)
{
	struct drbd_device *device = peer_device->device;
	int number, i, size;
	sector_t sector;
	const sector_t capacity = drbd_get_capacity(device->this_bdev);

	if (unlikely(cancel))
		return 1;

	number = drbd_rs_number_requests(peer_device);

	sector = peer_device->ov_position;
	for (i = 0; i < number; i++) {
		if (sector >= capacity) {
			return 1;
		}

		size = BM_BLOCK_SIZE;

		if (drbd_rs_should_slow_down(peer_device, sector) ||
		    drbd_try_rs_begin_io(peer_device, sector)) {
			peer_device->ov_position = sector;
			goto requeue;
		}

		if (sector + (size>>9) > capacity)
			size = (capacity-sector)<<9;

		inc_rs_pending(peer_device);
		if (drbd_send_ov_request(peer_device, sector, size)) {
			dec_rs_pending(peer_device);
			return 0;
		}
		sector += BM_SECT_PER_BIT;
	}
	peer_device->ov_position = sector;

 requeue:
	peer_device->rs_in_flight += (i << (BM_BLOCK_SHIFT - 9));
	mod_timer(&peer_device->resync_timer, jiffies + SLEEP_TIME);
	return 1;
}

int w_ov_finished(struct drbd_work *w, int cancel)
{
	struct drbd_peer_device_work *dw =
		container_of(w, struct drbd_peer_device_work, w);
	struct drbd_peer_device *peer_device = dw->peer_device;
	kfree(dw);
	ov_out_of_sync_print(peer_device);
	drbd_resync_finished(peer_device);

	return 0;
}

STATIC int w_resync_finished(struct drbd_work *w, int cancel)
{
	struct drbd_peer_device_work *dw =
		container_of(w, struct drbd_peer_device_work, w);
	struct drbd_peer_device *peer_device = dw->peer_device;
	kfree(dw);
	drbd_resync_finished(peer_device);

	return 0;
}

static void ping_peer(struct drbd_connection *connection)
{
	clear_bit(GOT_PING_ACK, &connection->flags);
	request_ping(connection);
	wait_event(connection->ping_wait,
		   test_bit(GOT_PING_ACK, &connection->flags) ||
		   connection->cstate[NOW] < C_CONNECTED);
}

int drbd_resync_finished(struct drbd_peer_device *peer_device)
{
	struct drbd_device *device = peer_device->device;
	struct drbd_connection *connection = peer_device->connection;
	enum drbd_repl_state *repl_state = peer_device->repl_state;
	unsigned long db, dt, dbdt;
	unsigned long n_oos;
	char *khelper_cmd = NULL;
	int verify_done = 0;
	unsigned long irq_flags;

	/* Remove all elements from the resync LRU. Since future actions
	 * might set bits in the (main) bitmap, then the entries in the
	 * resync LRU would be wrong. */
	if (drbd_rs_del_all(peer_device)) {
		struct drbd_peer_device_work *dw;

		/* In case this is not possible now, most probably because
		 * there are P_RS_DATA_REPLY Packets lingering on the sender's
		 * queue (or even the read operations for those packets
		 * is not finished by now).   Retry in 100ms. */

		schedule_timeout_interruptible(HZ / 10);
		dw = kmalloc(sizeof(*dw), GFP_ATOMIC);
		if (dw) {
			dw->w.cb = w_resync_finished;
			dw->peer_device = peer_device;
			drbd_queue_work(&connection->sender_work, &dw->w);
			return 1;
		}
		drbd_err(peer_device, "Warn failed to drbd_rs_del_all() and to kmalloc(dw).\n");
	}

	dt = (jiffies - peer_device->rs_start - peer_device->rs_paused) / HZ;
	if (dt <= 0)
		dt = 1;
	db = peer_device->rs_total;
	dbdt = Bit2KB(db/dt);
	peer_device->rs_paused /= HZ;

	if (!get_ldev(device))
		goto out;

	ping_peer(connection);

	begin_state_change(device->resource, &irq_flags, CS_VERBOSE);

	verify_done = (repl_state[NOW] == L_VERIFY_S || repl_state[NOW] == L_VERIFY_T);

	/* This protects us against multiple calls (that can happen in the presence
	   of application IO), and against connectivity loss just before we arrive here. */
	if (peer_device->repl_state[NOW] <= L_CONNECTED)
		goto out_unlock;
	__change_repl_state(peer_device, L_CONNECTED);

	drbd_info(device, "%s done (total %lu sec; paused %lu sec; %lu K/sec)\n",
	     verify_done ? "Online verify " : "Resync",
	     dt + peer_device->rs_paused, peer_device->rs_paused, dbdt);

	n_oos = drbd_bm_total_weight(peer_device);

	if (repl_state[NOW] == L_VERIFY_S || repl_state[NOW] == L_VERIFY_T) {
		if (n_oos) {
			drbd_alert(device, "Online verify found %lu %dk block out of sync!\n",
			      n_oos, Bit2KB(1));
			khelper_cmd = "out-of-sync";
		}
	} else {
		D_ASSERT(device, (n_oos - peer_device->rs_failed) == 0);

		if (repl_state[NOW] == L_SYNC_TARGET || repl_state[NOW] == L_PAUSED_SYNC_T)
			khelper_cmd = "after-resync-target";

		if (connection->csums_tfm && peer_device->rs_total) {
			const unsigned long s = peer_device->rs_same_csum;
			const unsigned long t = peer_device->rs_total;
			const int ratio =
				(t == 0)     ? 0 :
			(t < 100000) ? ((s*100)/t) : (s/(t/100));
			drbd_info(device, "%u %% had equal checksums, eliminated: %luK; "
			     "transferred %luK total %luK\n",
			     ratio,
			     Bit2KB(peer_device->rs_same_csum),
			     Bit2KB(peer_device->rs_total - peer_device->rs_same_csum),
			     Bit2KB(peer_device->rs_total));
		}
	}

	if (peer_device->rs_failed) {
		drbd_info(device, "            %lu failed blocks\n", peer_device->rs_failed);

		if (repl_state[NOW] == L_SYNC_TARGET || repl_state[NOW] == L_PAUSED_SYNC_T) {
			__change_disk_state(device, D_INCONSISTENT);
			__change_peer_disk_state(peer_device, D_UP_TO_DATE);
		} else {
			__change_disk_state(device, D_UP_TO_DATE);
			__change_peer_disk_state(peer_device, D_INCONSISTENT);
		}
	} else {
		__change_disk_state(device, D_UP_TO_DATE);
		__change_peer_disk_state(peer_device, D_UP_TO_DATE);

		if (repl_state[NOW] == L_SYNC_TARGET || repl_state[NOW] == L_PAUSED_SYNC_T) {
			if (peer_device->p_uuid) {
				int i;
				for (i = UI_BITMAP ; i <= UI_HISTORY_END ; i++)
					_drbd_uuid_set(peer_device, i, peer_device->p_uuid[i]);
				drbd_uuid_set(peer_device, UI_BITMAP, drbd_uuid(peer_device, UI_CURRENT));
				_drbd_uuid_set(peer_device, UI_CURRENT, peer_device->p_uuid[UI_CURRENT]);
			} else {
				drbd_err(device, "peer_device->p_uuid is NULL! BUG\n");
			}
		}

		if (!(repl_state[NOW] == L_VERIFY_S || repl_state[NOW] == L_VERIFY_T)) {
			/* for verify runs, we don't update uuids here,
			 * so there would be nothing to report. */
			drbd_uuid_set_bm(peer_device, 0UL);
			drbd_print_uuids(peer_device, "updated UUIDs");
			if (peer_device->p_uuid) {
				/* Now the two UUID sets are equal, update what we
				 * know of the peer. */
				int i;
				for (i = UI_CURRENT ; i <= UI_HISTORY_END ; i++)
					peer_device->p_uuid[i] = drbd_uuid(peer_device, i);
			}
		}
	}

out_unlock:
	end_state_change(device->resource, &irq_flags);
	put_ldev(device);
out:
	peer_device->rs_total  = 0;
	peer_device->rs_failed = 0;
	peer_device->rs_paused = 0;
	if (verify_done)
		peer_device->ov_start_sector = 0;

	drbd_md_sync(device);

	if (khelper_cmd)
		drbd_khelper(device, connection, khelper_cmd);

	return 1;
}

/* helper */
static void move_to_net_ee_or_free(struct drbd_device *device, struct drbd_peer_request *peer_req)
{
	if (drbd_peer_req_has_active_page(peer_req)) {
		/* This might happen if sendpage() has not finished */
		int i = (peer_req->i.size + PAGE_SIZE -1) >> PAGE_SHIFT;
		atomic_add(i, &device->pp_in_use_by_net);
		atomic_sub(i, &device->pp_in_use);
		spin_lock_irq(&device->resource->req_lock);
		list_add_tail(&peer_req->w.list, &device->net_ee);
		spin_unlock_irq(&device->resource->req_lock);
		wake_up(&drbd_pp_wait);
	} else
		drbd_free_peer_req(device, peer_req);
}

/**
 * w_e_end_data_req() - Worker callback, to send a P_DATA_REPLY packet in response to a P_DATA_REQUEST
 * @device:	DRBD device.
 * @w:		work object.
 * @cancel:	The connection will be closed anyways
 */
int w_e_end_data_req(struct drbd_work *w, int cancel)
{
	struct drbd_peer_request *peer_req = container_of(w, struct drbd_peer_request, w);
	struct drbd_peer_device *peer_device = peer_req->peer_device;
	struct drbd_device *device = peer_device->device;
	int err;

	if (unlikely(cancel)) {
		drbd_free_peer_req(device, peer_req);
		dec_unacked(peer_device);
		return 0;
	}

	if (likely((peer_req->flags & EE_WAS_ERROR) == 0)) {
		err = drbd_send_block(peer_device, P_DATA_REPLY, peer_req);
	} else {
		if (drbd_ratelimit())
			drbd_err(device, "Sending NegDReply. sector=%llus.\n",
			    (unsigned long long)peer_req->i.sector);

		err = drbd_send_ack(peer_device, P_NEG_DREPLY, peer_req);
	}

	dec_unacked(peer_device);

	move_to_net_ee_or_free(device, peer_req);

	if (unlikely(err))
		drbd_err(device, "drbd_send_block() failed\n");
	return err;
}

/**
 * w_e_end_rsdata_req() - Worker callback to send a P_RS_DATA_REPLY packet in response to a P_RS_DATA_REQUEST
 * @w:		work object.
 * @cancel:	The connection will be closed anyways
 */
int w_e_end_rsdata_req(struct drbd_work *w, int cancel)
{
	struct drbd_peer_request *peer_req = container_of(w, struct drbd_peer_request, w);
	struct drbd_peer_device *peer_device = peer_req->peer_device;
	struct drbd_device *device = peer_device->device;
	int err;

	if (unlikely(cancel)) {
		drbd_free_peer_req(device, peer_req);
		dec_unacked(peer_device);
		return 0;
	}

	if (get_ldev_if_state(device, D_FAILED)) {
		drbd_rs_complete_io(peer_device, peer_req->i.sector);
		put_ldev(device);
	}

	if (peer_device->repl_state[NOW] == L_AHEAD) {
		err = drbd_send_ack(peer_device, P_RS_CANCEL, peer_req);
	} else if (likely((peer_req->flags & EE_WAS_ERROR) == 0)) {
		if (likely(peer_device->disk_state[NOW] >= D_INCONSISTENT)) {
			inc_rs_pending(peer_device);
			err = drbd_send_block(peer_device, P_RS_DATA_REPLY, peer_req);
		} else {
			if (drbd_ratelimit())
				drbd_err(device, "Not sending RSDataReply, "
				    "partner DISKLESS!\n");
			err = 0;
		}
	} else {
		if (drbd_ratelimit())
			drbd_err(device, "Sending NegRSDReply. sector %llus.\n",
			    (unsigned long long)peer_req->i.sector);

		err = drbd_send_ack(peer_device, P_NEG_RS_DREPLY, peer_req);

		/* update resync data with failure */
		drbd_rs_failed_io(peer_device, peer_req->i.sector, peer_req->i.size);
	}

	dec_unacked(peer_device);

	move_to_net_ee_or_free(device, peer_req);

	if (unlikely(err))
		drbd_err(device, "drbd_send_block() failed\n");
	return err;
}

int w_e_end_csum_rs_req(struct drbd_work *w, int cancel)
{
	struct drbd_peer_request *peer_req = container_of(w, struct drbd_peer_request, w);
	struct drbd_peer_device *peer_device = peer_req->peer_device;
	struct drbd_device *device = peer_device->device;
	struct digest_info *di;
	int digest_size;
	void *digest = NULL;
	int err, eq = 0;

	if (unlikely(cancel)) {
		drbd_free_peer_req(device, peer_req);
		dec_unacked(peer_device);
		return 0;
	}

	if (get_ldev(device)) {
		drbd_rs_complete_io(peer_device, peer_req->i.sector);
		put_ldev(device);
	}

	di = peer_req->digest;

	if (likely((peer_req->flags & EE_WAS_ERROR) == 0)) {
		/* quick hack to try to avoid a race against reconfiguration.
		 * a real fix would be much more involved,
		 * introducing more locking mechanisms */
		if (peer_device->connection->csums_tfm) {
			digest_size = crypto_hash_digestsize(peer_device->connection->csums_tfm);
			D_ASSERT(device, digest_size == di->digest_size);
			digest = kmalloc(digest_size, GFP_NOIO);
		}
		if (digest) {
			drbd_csum_ee(peer_device->connection->csums_tfm, peer_req, digest);
			eq = !memcmp(digest, di->digest, digest_size);
			kfree(digest);
		}

		if (eq) {
			drbd_set_in_sync(peer_device, peer_req->i.sector, peer_req->i.size);
			/* rs_same_csums unit is BM_BLOCK_SIZE */
			peer_device->rs_same_csum += peer_req->i.size >> BM_BLOCK_SHIFT;
			err = drbd_send_ack(peer_device, P_RS_IS_IN_SYNC, peer_req);
		} else {
			inc_rs_pending(peer_device);
			peer_req->block_id = ID_SYNCER; /* By setting block_id, digest pointer becomes invalid! */
			peer_req->flags &= ~EE_HAS_DIGEST; /* This peer request no longer has a digest pointer */
			kfree(di);
			err = drbd_send_block(peer_device, P_RS_DATA_REPLY, peer_req);
		}
	} else {
		err = drbd_send_ack(peer_device, P_NEG_RS_DREPLY, peer_req);
		if (drbd_ratelimit())
			drbd_err(device, "Sending NegDReply. I guess it gets messy.\n");
	}

	dec_unacked(peer_device);
	move_to_net_ee_or_free(device, peer_req);

	if (unlikely(err))
		drbd_err(device, "drbd_send_block/ack() failed\n");
	return err;
}

int w_e_end_ov_req(struct drbd_work *w, int cancel)
{
	struct drbd_peer_request *peer_req = container_of(w, struct drbd_peer_request, w);
	struct drbd_peer_device *peer_device = peer_req->peer_device;
	struct drbd_device *device = peer_device->device;
	sector_t sector = peer_req->i.sector;
	unsigned int size = peer_req->i.size;
	int digest_size;
	void *digest;
	int err = 0;

	if (unlikely(cancel))
		goto out;

	digest_size = crypto_hash_digestsize(peer_device->connection->verify_tfm);
	/* FIXME if this allocation fails, online verify will not terminate! */
	digest = kmalloc(digest_size, GFP_NOIO);
	if (!digest) {
		err = -ENOMEM;
		goto out;
	}

	if (!(peer_req->flags & EE_WAS_ERROR))
		drbd_csum_ee(peer_device->connection->verify_tfm, peer_req, digest);
	else
		memset(digest, 0, digest_size);

	/* Free peer_req and pages before send.
	 * In case we block on congestion, we could otherwise run into
	 * some distributed deadlock, if the other side blocks on
	 * congestion as well, because our receiver blocks in
	 * drbd_alloc_pages due to pp_in_use > max_buffers. */
	drbd_free_peer_req(device, peer_req);
	peer_req = NULL;

	inc_rs_pending(peer_device);
	err = drbd_send_drequest_csum(peer_device, sector, size, digest, digest_size, P_OV_REPLY);
	if (err)
		dec_rs_pending(peer_device);
	kfree(digest);

out:
	if (peer_req)
		drbd_free_peer_req(device, peer_req);
	dec_unacked(peer_device);
	return err;
}

void drbd_ov_out_of_sync_found(struct drbd_peer_device *peer_device, sector_t sector, int size)
{
	if (peer_device->ov_last_oos_start + peer_device->ov_last_oos_size == sector) {
		peer_device->ov_last_oos_size += size>>9;
	} else {
		peer_device->ov_last_oos_start = sector;
		peer_device->ov_last_oos_size = size>>9;
	}
	drbd_set_out_of_sync(peer_device, sector, size);
}

int w_e_end_ov_reply(struct drbd_work *w, int cancel)
{
	struct drbd_peer_request *peer_req = container_of(w, struct drbd_peer_request, w);
	struct drbd_peer_device *peer_device = peer_req->peer_device;
	struct drbd_device *device = peer_device->device;
	struct digest_info *di;
	void *digest;
	sector_t sector = peer_req->i.sector;
	unsigned int size = peer_req->i.size;
	int digest_size;
	int err, eq = 0;

	if (unlikely(cancel)) {
		drbd_free_peer_req(device, peer_req);
		dec_unacked(peer_device);
		return 0;
	}

	/* after "cancel", because after drbd_disconnect/drbd_rs_cancel_all
	 * the resync lru has been cleaned up already */
	if (get_ldev(device)) {
		drbd_rs_complete_io(peer_device, peer_req->i.sector);
		put_ldev(device);
	}

	di = peer_req->digest;

	if (likely((peer_req->flags & EE_WAS_ERROR) == 0)) {
		digest_size = crypto_hash_digestsize(peer_device->connection->verify_tfm);
		digest = kmalloc(digest_size, GFP_NOIO);
		if (digest) {
			drbd_csum_ee(peer_device->connection->verify_tfm, peer_req, digest);

			D_ASSERT(device, digest_size == di->digest_size);
			eq = !memcmp(digest, di->digest, digest_size);
			kfree(digest);
		}
	}

	/* Free peer_req and pages before send.
	 * In case we block on congestion, we could otherwise run into
	 * some distributed deadlock, if the other side blocks on
	 * congestion as well, because our receiver blocks in
	 * drbd_alloc_pages due to pp_in_use > max_buffers. */
	drbd_free_peer_req(device, peer_req);
	if (!eq)
		drbd_ov_out_of_sync_found(peer_device, sector, size);
	else
		ov_out_of_sync_print(peer_device);

	err = drbd_send_ack_ex(peer_device, P_OV_RESULT, sector, size,
			       eq ? ID_IN_SYNC : ID_OUT_OF_SYNC);

	dec_unacked(peer_device);

	--peer_device->ov_left;

	/* let's advance progress step marks only for every other megabyte */
	if ((peer_device->ov_left & 0x200) == 0x200)
		drbd_advance_rs_marks(peer_device, peer_device->ov_left);

	if (peer_device->ov_left == 0) {
		ov_out_of_sync_print(peer_device);
		drbd_resync_finished(peer_device);
	}

	return err;
}

int w_send_barrier(struct drbd_work *w, int cancel)
{
	struct drbd_socket *sock;
	struct drbd_tl_epoch *b = container_of(w, struct drbd_tl_epoch, w);
	struct drbd_device *device = b->device;
	struct p_barrier *p;

	/* really avoid racing with tl_clear.  w.cb may have been referenced
	 * just before it was reassigned and re-queued, so double check that.
	 * actually, this race was harmless, since we only try to send the
	 * barrier packet here, and otherwise do nothing with the object.
	 * but compare with the head of w_clear_epoch */
	spin_lock_irq(&device->resource->req_lock);
	if (w->cb != w_send_barrier || first_peer_device(device)->repl_state[NOW] < L_CONNECTED)
		cancel = 1;
	spin_unlock_irq(&device->resource->req_lock);
	if (cancel)
		return 0;

	sock = &first_peer_device(device)->connection->data;
	p = drbd_prepare_command(first_peer_device(device), sock);
	if (!p)
		return -EIO;
	p->barrier = b->br_number;
	/* inc_ap_pending was done where this was queued.
	 * dec_ap_pending will be done in got_BarrierAck
	 * or (on connection loss) in w_clear_epoch.  */
	return drbd_send_command(first_peer_device(device), sock, P_BARRIER, sizeof(*p), NULL, 0);
}

int w_send_write_hint(struct drbd_work *w, int cancel)
{
	struct drbd_device *device =
		container_of(w, struct drbd_device, unplug_work);
	struct drbd_socket *sock;

	if (cancel)
		return 0;
	sock = &first_peer_device(device)->connection->data;
	if (!drbd_prepare_command(first_peer_device(device), sock))
		return -EIO;
	return drbd_send_command(first_peer_device(device), sock, P_UNPLUG_REMOTE, 0, NULL, 0);
}

int w_send_out_of_sync(struct drbd_work *w, int cancel)
{
	struct drbd_request *req = container_of(w, struct drbd_request, w);
	struct drbd_device *device = req->device;
	int err;

	if (unlikely(cancel)) {
		req_mod(req, SEND_CANCELED);
		return 0;
	}

	err = drbd_send_out_of_sync(first_peer_device(device), req);
	req_mod(req, OOS_HANDED_TO_NETWORK);

	return err;
}

/**
 * w_send_dblock() - Worker callback to send a P_DATA packet in order to mirror a write request
 * @device:	DRBD device.
 * @w:		work object.
 * @cancel:	The connection will be closed anyways
 */
int w_send_dblock(struct drbd_work *w, int cancel)
{
	struct drbd_request *req = container_of(w, struct drbd_request, w);
	struct drbd_device *device = req->device;
	int err;

	if (unlikely(cancel)) {
		req_mod(req, SEND_CANCELED);
		return 0;
	}

	err = drbd_send_dblock(first_peer_device(device), req);
	req_mod(req, err ? SEND_FAILED : HANDED_OVER_TO_NETWORK);

	return err;
}

/**
 * w_send_read_req() - Worker callback to send a read request (P_DATA_REQUEST) packet
 * @device:	DRBD device.
 * @w:		work object.
 * @cancel:	The connection will be closed anyways
 */
int w_send_read_req(struct drbd_work *w, int cancel)
{
	struct drbd_request *req = container_of(w, struct drbd_request, w);
	struct drbd_device *device = req->device;
	int err;

	if (unlikely(cancel)) {
		req_mod(req, SEND_CANCELED);
		return 0;
	}

	err = drbd_send_drequest(first_peer_device(device), P_DATA_REQUEST, req->i.sector, req->i.size,
				 (unsigned long)req);

	req_mod(req, err ? SEND_FAILED : HANDED_OVER_TO_NETWORK);

	return err;
}

int w_restart_disk_io(struct drbd_work *w, int cancel)
{
	struct drbd_request *req = container_of(w, struct drbd_request, w);
	struct drbd_device *device = req->device;

	if (bio_data_dir(req->master_bio) == WRITE && req->rq_state & RQ_IN_ACT_LOG)
		drbd_al_begin_io(device, &req->i, false);

	drbd_req_make_private_bio(req, req->master_bio);
	req->private_bio->bi_bdev = device->ldev->backing_bdev;
	generic_make_request(req->private_bio);

	return 0;
}

static bool __drbd_may_sync_now(struct drbd_peer_device *peer_device)
{
	struct drbd_device *other_device = peer_device->device;
	int ret = true;

	rcu_read_lock();
	while (1) {
		struct drbd_peer_device *other_peer_device;
		int resync_after;

		if (!other_device->ldev)
			break;
		resync_after = rcu_dereference(other_device->ldev->disk_conf)->resync_after;
		if (resync_after == -1)
			break;
		other_device = minor_to_mdev(resync_after);
		if (!expect(peer_device, other_device))
			break;
		other_peer_device = find_peer_device(other_device, peer_device->connection);
		if ((other_peer_device->repl_state[NOW] >= L_SYNC_SOURCE &&
		     other_peer_device->repl_state[NOW] <= L_PAUSED_SYNC_T) ||
		    other_peer_device->resync_susp_dependency[NOW] ||
		    other_peer_device->resync_susp_peer[NOW] ||
		    other_peer_device->resync_susp_user[NOW]) {
			ret = false;
			break;
		}
	}
	rcu_read_unlock();

	return ret;
}

/**
 * drbd_pause_after() - Pause resync on all devices that may not resync now
 * @device:	DRBD device.
 *
 * Called from process context only (admin command and after_state_ch).
 */
static bool drbd_pause_after(struct drbd_device *device)
{
	struct drbd_device *other_device;
	bool changed = false;
	int vnr;

	rcu_read_lock();
	idr_for_each_entry(&drbd_devices, other_device, vnr) {
		struct drbd_peer_device *other_peer_device;

		begin_state_change_locked(other_device->resource, CS_HARD);
		if (other_device->disk_state == D_DISKLESS) {
			abort_state_change_locked(other_device->resource);
			continue;
		}
		for_each_peer_device(other_peer_device, other_device) {
			if (other_peer_device->repl_state[NOW] == L_STANDALONE)
				continue;
			if (!__drbd_may_sync_now(other_peer_device))
				__change_resync_susp_dependency(other_peer_device, true);
		}
		if (end_state_change_locked(other_device->resource) != SS_NOTHING_TO_DO)
			changed = true;
	}
	rcu_read_unlock();
	return changed;
}

/**
 * drbd_resume_next() - Resume resync on all devices that may resync now
 * @device:	DRBD device.
 *
 * Called from process context only (admin command and sender).
 */
static bool drbd_resume_next(struct drbd_device *device)
{
	struct drbd_device *other_device;
	bool changed = false;
	int vnr;

	rcu_read_lock();
	idr_for_each_entry(&drbd_devices, other_device, vnr) {
		struct drbd_peer_device *other_peer_device;

		begin_state_change_locked(other_device->resource, CS_HARD);
		if (other_device->disk_state == D_DISKLESS) {
			abort_state_change_locked(other_device->resource);
			continue;
		}
		for_each_peer_device(other_peer_device, other_device) {
			if (other_peer_device->repl_state[NOW] == L_STANDALONE)
				continue;
			if (other_peer_device->resync_susp_dependency[NOW] &&
			    __drbd_may_sync_now(other_peer_device))
				__change_resync_susp_dependency(other_peer_device, false);
		}
		if (end_state_change_locked(other_device->resource) != SS_NOTHING_TO_DO)
			changed = true;
	}
	rcu_read_unlock();
	return changed;
}

void resume_next_sg(struct drbd_device *device)
{
	lock_all_resources();
	drbd_resume_next(device);
	unlock_all_resources();
}

void suspend_other_sg(struct drbd_device *device)
{
	lock_all_resources();
	drbd_pause_after(device);
	unlock_all_resources();
}

/* caller must hold global_state_mutex */
enum drbd_ret_code drbd_resync_after_valid(struct drbd_device *device, int resync_after)
{
	struct drbd_device *other_device;
	int rv = NO_ERROR;

	if (resync_after == -1)
		return NO_ERROR;
	if (resync_after < -1)
		return ERR_RESYNC_AFTER;
	other_device = minor_to_mdev(resync_after);
	if (!other_device)
		return ERR_RESYNC_AFTER;

	/* check for loops */
	rcu_read_lock();
	while (1) {
		if (other_device == device) {
			rv = ERR_RESYNC_AFTER_CYCLE;
			break;
		}

		resync_after = rcu_dereference(other_device->ldev->disk_conf)->resync_after;
		/* dependency chain ends here, no cycles. */
		if (resync_after == -1)
			break;

		/* follow the dependency chain */
		other_device = minor_to_mdev(resync_after);
	}
	rcu_read_unlock();

	return rv;
}

/* caller must hold global_state_mutex */
void drbd_resync_after_changed(struct drbd_device *device)
{
	while (drbd_pause_after(device) || drbd_resume_next(device))
		/* do nothing */ ;
}

void drbd_rs_controller_reset(struct drbd_peer_device *peer_device)
{
	struct fifo_buffer *plan;

	atomic_set(&peer_device->rs_sect_in, 0);
	atomic_set(&peer_device->device->rs_sect_ev, 0);  /* FIXME: ??? */
	peer_device->rs_in_flight = 0;

	/* Updating the RCU protected object in place is necessary since
	   this function gets called from atomic context.
	   It is valid since all other updates also lead to an completely
	   empty fifo */
	rcu_read_lock();
	plan = rcu_dereference(peer_device->rs_plan_s);
	plan->total = 0;
	fifo_set(plan, 0);
	rcu_read_unlock();
}

void start_resync_timer_fn(unsigned long data)
{
	struct drbd_peer_device *peer_device = (struct drbd_peer_device *) data;
	struct drbd_resource *resource = peer_device->device->resource;

	drbd_queue_work(&resource->work, &peer_device->start_resync_work);
}

int w_start_resync(struct drbd_work *w, int cancel)
{
	struct drbd_peer_device *peer_device =
		container_of(w, struct drbd_peer_device, start_resync_work);
	struct drbd_device *device = peer_device->device;

	if (atomic_read(&peer_device->unacked_cnt) ||
	    atomic_read(&peer_device->rs_pending_cnt)) {
		drbd_warn(peer_device, "w_start_resync later...\n");
		peer_device->start_resync_timer.expires = jiffies + HZ/10;
		add_timer(&peer_device->start_resync_timer);
		return 0;
	}

	drbd_start_resync(peer_device, L_SYNC_SOURCE);
	clear_bit(AHEAD_TO_SYNC_SOURCE, &device->flags);
	return 0;
}

/**
 * drbd_start_resync() - Start the resync process
 * @side:	Either L_SYNC_SOURCE or L_SYNC_TARGET
 *
 * This function might bring you directly into one of the
 * C_PAUSED_SYNC_* states.
 */
void drbd_start_resync(struct drbd_peer_device *peer_device, enum drbd_repl_state side)
{
	struct drbd_device *device = peer_device->device;
	struct drbd_connection *connection = peer_device->connection;
	enum drbd_repl_state repl_state;
	int r;

	if (peer_device->repl_state[NOW] >= L_SYNC_SOURCE && peer_device->repl_state[NOW] < L_AHEAD) {
		drbd_err(peer_device, "Resync already running!\n");
		return;
	}

	if (peer_device->repl_state[NOW] < L_AHEAD) {
		/* In case a previous resync run was aborted by an IO error/detach on the peer. */
		drbd_rs_cancel_all(peer_device);
		/* This should be done when we abort the resync. We definitely do not
		   want to have this for connections going back and forth between
		   Ahead/Behind and SyncSource/SyncTarget */
	}

	if (!test_bit(B_RS_H_DONE, &peer_device->flags)) {
		if (side == L_SYNC_TARGET) {
			/* Since application IO was locked out during L_WF_BITMAP_T and
			   L_WF_SYNC_UUID we are still unmodified. Before going to L_SYNC_TARGET
			   we check that we might make the data inconsistent. */
			r = drbd_khelper(device, connection, "before-resync-target");
			r = (r >> 8) & 0xff;
			if (r > 0) {
				drbd_info(device, "before-resync-target handler returned %d, "
					 "dropping connection.\n", r);
				change_cstate(connection, C_DISCONNECTING, CS_HARD);
				return;
			}
		} else /* L_SYNC_SOURCE */ {
			r = drbd_khelper(device, connection, "before-resync-source");
			r = (r >> 8) & 0xff;
			if (r > 0) {
				if (r == 3) {
					drbd_info(device, "before-resync-source handler returned %d, "
						 "ignoring. Old userland tools?", r);
				} else {
					drbd_info(device, "before-resync-source handler returned %d, "
						 "dropping connection.\n", r);
					change_cstate(connection, C_DISCONNECTING, CS_HARD);
					return;
				}
			}
		}
	}

	if (current == connection->sender.task) {
		/* The sender should not sleep waiting for state_mutex,
		   that can take long */
		set_bit(B_RS_H_DONE, &peer_device->flags);
		peer_device->start_resync_timer.expires = jiffies + HZ/5;
		add_timer(&peer_device->start_resync_timer);
		return;
	}

	mutex_lock(&device->resource->state_mutex);
	lock_all_resources();
	clear_bit(B_RS_H_DONE, &peer_device->flags);
	if (!get_ldev_if_state(device, D_NEGOTIATING)) {
		unlock_all_resources();
		goto out;
	}

	begin_state_change_locked(device->resource, CS_VERBOSE);
	__change_resync_susp_dependency(peer_device, !__drbd_may_sync_now(peer_device));
	__change_repl_state(peer_device, side);
	if (side == L_SYNC_TARGET)
		__change_disk_state(device, D_INCONSISTENT);
	else /* side == L_SYNC_SOURCE */
		__change_peer_disk_state(peer_device, D_INCONSISTENT);
	r = end_state_change_locked(device->resource);
	repl_state = peer_device->repl_state[NOW];

	if (repl_state < L_CONNECTED)
		r = SS_UNKNOWN_ERROR;

	if (r == SS_SUCCESS) {
		unsigned long tw = drbd_bm_total_weight(peer_device);
		unsigned long now = jiffies;
		int i;

		peer_device->rs_failed    = 0;
		peer_device->rs_paused    = 0;
		peer_device->rs_same_csum = 0;
		peer_device->rs_last_events = 0;
		peer_device->rs_last_sect_ev = 0;
		peer_device->rs_total     = tw;
		peer_device->rs_start     = now;
		for (i = 0; i < DRBD_SYNC_MARKS; i++) {
			peer_device->rs_mark_left[i] = tw;
			peer_device->rs_mark_time[i] = now;
		}
		drbd_pause_after(device);
	}
	unlock_all_resources();

	if (r == SS_SUCCESS) {
		drbd_info(peer_device, "Began resync as %s (will sync %lu KB [%lu bits set]).\n",
		     drbd_conn_str(repl_state),
		     (unsigned long) peer_device->rs_total << (BM_BLOCK_SHIFT-10),
		     (unsigned long) peer_device->rs_total);
		if (side == L_SYNC_TARGET)
			device->bm_resync_fo = 0;

		/* Since protocol 96, we must serialize drbd_gen_and_send_sync_uuid
		 * with w_send_oos, or the sync target will get confused as to
		 * how much bits to resync.  We cannot do that always, because for an
		 * empty resync and protocol < 95, we need to do it here, as we call
		 * drbd_resync_finished from here in that case.
		 * We drbd_gen_and_send_sync_uuid here for protocol < 96,
		 * and from after_state_ch otherwise. */
		if (side == L_SYNC_SOURCE && connection->agreed_pro_version < 96)
			drbd_gen_and_send_sync_uuid(peer_device);

		if (connection->agreed_pro_version < 95 && peer_device->rs_total == 0) {
			/* This still has a race (about when exactly the peers
			 * detect connection loss) that can lead to a full sync
			 * on next handshake. In 8.3.9 we fixed this with explicit
			 * resync-finished notifications, but the fix
			 * introduces a protocol change.  Sleeping for some
			 * time longer than the ping interval + timeout on the
			 * SyncSource, to give the SyncTarget the chance to
			 * detect connection loss, then waiting for a ping
			 * response (implicit in drbd_resync_finished) reduces
			 * the race considerably, but does not solve it. */
			if (side == L_SYNC_SOURCE) {
				struct net_conf *nc;
				int timeo;

				rcu_read_lock();
				nc = rcu_dereference(connection->net_conf);
				timeo = nc->ping_int * HZ + nc->ping_timeo * HZ / 9;
				rcu_read_unlock();
				schedule_timeout_interruptible(timeo);
			}
			drbd_resync_finished(peer_device);
		}

		drbd_rs_controller_reset(peer_device);
		/* ns.conn may already be != peer_device->repl_state[NOW],
		 * we may have been paused in between, or become paused until
		 * the timer triggers.
		 * No matter, that is handled in resync_timer_fn() */
		if (repl_state == L_SYNC_TARGET)
			mod_timer(&peer_device->resync_timer, jiffies);

		drbd_md_sync(device);
	}
	put_ldev(device);
    out:
	mutex_unlock(&device->resource->state_mutex);
}

bool dequeue_work_batch(struct drbd_work_queue *queue, struct list_head *work_list)
{
	spin_lock_irq(&queue->q_lock);
	list_splice_init(&queue->q, work_list);
	spin_unlock_irq(&queue->q_lock);
	return !list_empty(work_list);
}

int drbd_sender(struct drbd_thread *thi)
{
	LIST_HEAD(work_list);
	struct drbd_connection *connection = thi->connection;
	struct drbd_work *w;
	struct drbd_peer_device *peer_device;
	struct net_conf *nc;
	int vnr;
	int cork;

	rcu_read_lock();
	idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
		peer_device->send_cnt = 0;
		peer_device->recv_cnt = 0;
	}
	rcu_read_unlock();

	while (get_t_state(thi) == RUNNING) {

		drbd_thread_current_set_cpu(thi);

		if (list_empty(&work_list))
			dequeue_work_batch(&connection->sender_work, &work_list);

		/* Still nothing to do? Poke TCP, just in case,
		 * then wait for new work (or signal). */
		if (list_empty(&work_list)) {
			mutex_lock(&connection->data.mutex);
			rcu_read_lock();
			nc = rcu_dereference(connection->net_conf);
			cork = nc ? nc->tcp_cork : 0;
			rcu_read_unlock();

			if (connection->data.socket && cork)
				drbd_tcp_uncork(connection->data.socket);
			mutex_unlock(&connection->data.mutex);

			wait_event_interruptible(connection->sender_work.q_wait,
				dequeue_work_batch(&connection->sender_work, &work_list));

			mutex_lock(&connection->data.mutex);
			if (connection->data.socket && cork)
				drbd_tcp_cork(connection->data.socket);
			mutex_unlock(&connection->data.mutex);
		}

		if (signal_pending(current)) {
			flush_signals(current);
			if (get_t_state(thi) == RUNNING) {
				drbd_warn(connection, "Sender got an unexpected signal\n");
				continue;
			}
			break;
		}

		if (get_t_state(thi) != RUNNING)
			break;

		while (!list_empty(&work_list)) {
			w = list_first_entry(&work_list, struct drbd_work, list);
			list_del_init(&w->list);
			if (w->cb(w, connection->cstate[NOW] < C_CONNECTED) == 0)
				continue;
			if (connection->cstate[NOW] >= C_CONNECTED)
				change_cstate(connection, C_NETWORK_FAILURE, CS_HARD);
		}
	}

	do {
		while (!list_empty(&work_list)) {
			w = list_first_entry(&work_list, struct drbd_work, list);
			list_del_init(&w->list);
			w->cb(w, 1);
		}
		dequeue_work_batch(&connection->sender_work, &work_list);
	} while (!list_empty(&work_list));

	rcu_read_lock();
	idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
		struct drbd_device *device = peer_device->device;
		D_ASSERT(device, device->disk_state[NOW] == D_DISKLESS &&
			 peer_device->repl_state[NOW] == L_STANDALONE);
		kref_get(&device->kref);
		rcu_read_unlock();
		drbd_mdev_cleanup(device);  /* FIXME: we "clean up" the wrong stuff here! */
		kref_put(&device->kref, drbd_destroy_device);
		rcu_read_lock();
	}
	rcu_read_unlock();

	return 0;
}

int drbd_worker(struct drbd_thread *thi)
{
	LIST_HEAD(work_list);
	struct drbd_resource *resource = thi->resource;
	struct drbd_work *w;

	while (get_t_state(thi) == RUNNING) {
		drbd_thread_current_set_cpu(thi);

		if (list_empty(&work_list)) {
			wait_event_interruptible(resource->work.q_wait,
				dequeue_work_batch(&resource->work, &work_list));
		}

		if (signal_pending(current)) {
			flush_signals(current);
			if (get_t_state(thi) == RUNNING) {
				drbd_warn(resource, "Worker got an unexpected signal\n");
				continue;
			}
			break;
		}

		if (get_t_state(thi) != RUNNING)
			break;


		while (!list_empty(&work_list)) {
			w = list_first_entry(&work_list, struct drbd_work, list);
			list_del_init(&w->list);
			w->cb(w, 0);
		}
	}

	do {
		while (!list_empty(&work_list)) {
			w = list_first_entry(&work_list, struct drbd_work, list);
			list_del_init(&w->list);
			w->cb(w, 1);
		}
		dequeue_work_batch(&resource->work, &work_list);
	} while (!list_empty(&work_list));

	return 0;
}
