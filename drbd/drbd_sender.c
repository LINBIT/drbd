// SPDX-License-Identifier: GPL-2.0-or-later
/*
   drbd_sender.c

   This file is part of DRBD by Philipp Reisner and Lars Ellenberg.

   Copyright (C) 2001-2008, LINBIT Information Technologies GmbH.
   Copyright (C) 1999-2008, Philipp Reisner <philipp.reisner@linbit.com>.
   Copyright (C) 2002-2008, Lars Ellenberg <lars.ellenberg@linbit.com>.


 */

#include <linux/module.h>
#include <linux/drbd.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/wait.h>
#include <linux/mm.h>
#include <linux/memcontrol.h>
#include <linux/mm_inline.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/scatterlist.h>
#include <linux/overflow.h>
#include <linux/part_stat.h>

#include "drbd_int.h"
#include "drbd_protocol.h"
#include "drbd_req.h"

void drbd_panic_after_delayed_completion_of_aborted_request(struct drbd_device *device);

static int make_ov_request(struct drbd_peer_device *, int);
static int make_resync_request(struct drbd_peer_device *, int);
static bool should_send_barrier(struct drbd_connection *, unsigned int epoch);
static void maybe_send_barrier(struct drbd_connection *, unsigned int);
static unsigned long get_work_bits(const unsigned long mask, unsigned long *flags);

/* endio handlers:
 *   drbd_md_endio (defined here)
 *   drbd_request_endio (defined here)
 *   drbd_peer_request_endio (defined here)
 *   drbd_bm_endio (defined in drbd_bitmap.c)
 *
 * For all these callbacks, note the following:
 * The callbacks will be called in irq context by the IDE drivers,
 * and in Softirqs/Tasklets/BH context by the SCSI drivers.
 * Try to get the locking right :)
 *
 */

struct mutex resources_mutex;

/* used for synchronous meta data and bitmap IO
 * submitted by drbd_md_sync_page_io()
 */
void drbd_md_endio(struct bio *bio)
{
	struct drbd_device *device;

	blk_status_t status = bio->bi_status;

	device = bio->bi_private;
	device->md_io.error = blk_status_to_errno(status);

	/* special case: drbd_md_read() during drbd_adm_attach() */
	if (device->ldev)
		put_ldev(device);
	bio_put(bio);

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
	device->md_io.done = 1;
	wake_up(&device->misc_wait);
}

/* reads on behalf of the partner,
 * "submitted" by the receiver
 */
static void drbd_endio_read_sec_final(struct drbd_peer_request *peer_req) __releases(local)
{
	unsigned long flags = 0;
	struct drbd_peer_device *peer_device = peer_req->peer_device;
	struct drbd_device *device = peer_device->device;
	struct drbd_connection *connection = peer_device->connection;

	spin_lock_irqsave(&device->resource->req_lock, flags);
	device->read_cnt += peer_req->i.size >> 9;
	list_del(&peer_req->w.list);
	if (list_empty(&connection->read_ee))
		wake_up(&connection->ee_wait);
	if (test_bit(__EE_WAS_ERROR, &peer_req->flags))
		__drbd_chk_io_error(device, DRBD_READ_ERROR);
	spin_unlock_irqrestore(&device->resource->req_lock, flags);

	drbd_queue_work(&connection->sender_work, &peer_req->w);
	put_ldev(device);
}

static int is_failed_barrier(int ee_flags)
{
	return (ee_flags & (EE_IS_BARRIER|EE_WAS_ERROR|EE_RESUBMITTED|EE_TRIM|EE_ZEROOUT))
		== (EE_IS_BARRIER|EE_WAS_ERROR);
}

/* writes on behalf of the partner, or resync writes,
 * "submitted" by the receiver, final stage.  */
void drbd_endio_write_sec_final(struct drbd_peer_request *peer_req) __releases(local)
{
	unsigned long flags = 0;
	struct drbd_peer_device *peer_device = peer_req->peer_device;
	struct drbd_device *device = peer_device->device;
	struct drbd_connection *connection = peer_device->connection;
	sector_t sector;
	int do_wake;
	u64 block_id;

	/* if this is a failed barrier request, disable use of barriers,
	 * and schedule for resubmission */
	if (is_failed_barrier(peer_req->flags)) {
		drbd_bump_write_ordering(device->resource, device->ldev, WO_BDEV_FLUSH);
		spin_lock_irqsave(&device->resource->req_lock, flags);
		list_del(&peer_req->w.list);
		peer_req->flags = (peer_req->flags & ~EE_WAS_ERROR) | EE_RESUBMITTED;
		peer_req->w.cb = w_e_reissue;
		/* put_ldev actually happens below, once we come here again. */
		__release(local);
		spin_unlock_irqrestore(&device->resource->req_lock, flags);
		drbd_queue_work(&connection->sender_work, &peer_req->w);
		if (atomic_dec_and_test(&connection->active_ee_cnt))
			wake_up(&connection->ee_wait);
		return;
	}

	/* after we moved peer_req to done_ee,
	 * we may no longer access it,
	 * it may be freed/reused already!
	 * (as soon as we release the req_lock) */
	sector = peer_req->i.sector;
	block_id = peer_req->block_id;

	if (peer_req->flags & EE_WAS_ERROR) {
                /* In protocol != C, we usually do not send write acks.
                 * In case of a write error, send the neg ack anyways. */
                if (!__test_and_set_bit(__EE_SEND_WRITE_ACK, &peer_req->flags))
                        inc_unacked(peer_device);
                drbd_set_out_of_sync(peer_device, peer_req->i.sector, peer_req->i.size);
        }

	spin_lock_irqsave(&device->resource->req_lock, flags);
	device->writ_cnt += peer_req->i.size >> 9;
	atomic_inc(&connection->done_ee_cnt);
	list_move_tail(&peer_req->w.list, &connection->done_ee);

	/*
	 * Do not remove from the write_requests tree here: we did not send the
	 * Ack yet and did not wake possibly waiting conflicting requests.
	 * Removed from the tree from "drbd_process_done_ee" within the
	 * appropriate callback (e_end_block/e_end_resync_block) or from
	 * _drbd_clear_done_ee.
	 */

	if (block_id == ID_SYNCER)
		do_wake = list_empty(&connection->sync_ee);
	else
		do_wake = atomic_dec_and_test(&connection->active_ee_cnt);

	/* FIXME do we want to detach for failed REQ_OP_DISCARD?
	 * ((peer_req->flags & (EE_WAS_ERROR|EE_TRIM)) == EE_WAS_ERROR) */
	if (peer_req->flags & EE_WAS_ERROR)
		__drbd_chk_io_error(device, DRBD_WRITE_ERROR);

	if (connection->cstate[NOW] == C_CONNECTED)
		queue_work(connection->ack_sender, &connection->send_acks_work);
	spin_unlock_irqrestore(&device->resource->req_lock, flags);

	if (block_id == ID_SYNCER)
		drbd_rs_complete_io(peer_device, sector);

	if (do_wake)
		wake_up(&connection->ee_wait);

	put_ldev(device);
}

/* writes on behalf of the partner, or resync writes,
 * "submitted" by the receiver.
 */
void drbd_peer_request_endio(struct bio *bio)
{
	struct drbd_peer_request *peer_req = bio->bi_private;
	struct drbd_device *device = peer_req->peer_device->device;
	bool is_write = bio_data_dir(bio) == WRITE;
	bool is_discard = bio_op(bio) == REQ_OP_WRITE_ZEROES ||
			  bio_op(bio) == REQ_OP_DISCARD;

	blk_status_t status = bio->bi_status;

	if (status && drbd_ratelimit())
		drbd_warn(device, "%s: error=%d s=%llus\n",
				is_write ? (is_discard ? "discard" : "write")
					: "read", status,
				(unsigned long long)peer_req->i.sector);

	if (status)
		set_bit(__EE_WAS_ERROR, &peer_req->flags);

	bio_put(bio); /* no need for the bio anymore */
	if (atomic_dec_and_test(&peer_req->pending_bios)) {
		if (is_write)
			drbd_endio_write_sec_final(peer_req);
		else
			drbd_endio_read_sec_final(peer_req);
	}
}

/* Not static to increase the likelyhood that it will show up in a stack trace */
void drbd_panic_after_delayed_completion_of_aborted_request(struct drbd_device *device)
{
	panic("drbd%u %s/%u potential random memory corruption caused by delayed completion of aborted local request\n",
		device->minor, device->resource->name, device->vnr);
}


/* read, readA or write requests on R_PRIMARY coming from drbd_submit_bio
 */
void drbd_request_endio(struct bio *bio)
{
	unsigned long flags;
	struct drbd_request *req = bio->bi_private;
	struct drbd_device *device = req->device;
	struct bio_and_error m;
	enum drbd_req_event what;

	blk_status_t status = bio->bi_status;

	/* If this request was aborted locally before,
	 * but now was completed "successfully",
	 * chances are that this caused arbitrary data corruption.
	 *
	 * "aborting" requests, or force-detaching the disk, is intended for
	 * completely blocked/hung local backing devices which do no longer
	 * complete requests at all, not even do error completions.  In this
	 * situation, usually a hard-reset and failover is the only way out.
	 *
	 * By "aborting", basically faking a local error-completion,
	 * we allow for a more graceful switchover by cleanly migrating services.
	 * Still the affected node has to be rebooted "soon".
	 *
	 * By completing these requests, we allow the upper layers to re-use
	 * the associated data pages.
	 *
	 * If later the local backing device "recovers", and now DMAs some data
	 * from disk into the original request pages, in the best case it will
	 * just put random data into unused pages; but typically it will corrupt
	 * meanwhile completely unrelated data, causing all sorts of damage.
	 *
	 * Which means delayed successful completion,
	 * especially for READ requests,
	 * is a reason to panic().
	 *
	 * We assume that a delayed *error* completion is OK,
	 * though we still will complain noisily about it.
	 */
	if (unlikely(req->local_rq_state & RQ_LOCAL_ABORTED)) {
		if (drbd_ratelimit())
			drbd_emerg(device, "delayed completion of aborted local request; disk-timeout may be too aggressive\n");

		if (!status)
			drbd_panic_after_delayed_completion_of_aborted_request(device);
	}

	/* to avoid recursion in __req_mod */
	if (unlikely(status)) {
		unsigned int op = bio_op(bio);
		if (op == REQ_OP_DISCARD || op == REQ_OP_WRITE_ZEROES) {
			if (status == BLK_STS_NOTSUPP)
				what = DISCARD_COMPLETED_NOTSUPP;
			else
				what = DISCARD_COMPLETED_WITH_ERROR;
		} else if (op == REQ_OP_READ) {
			if (bio->bi_opf & REQ_RAHEAD)
				what = READ_AHEAD_COMPLETED_WITH_ERROR;
			else
				what = READ_COMPLETED_WITH_ERROR;
		} else {
			what = WRITE_COMPLETED_WITH_ERROR;
		}
	} else {
		what = COMPLETED_OK;
	}

	bio_put(req->private_bio);
	req->private_bio = ERR_PTR(blk_status_to_errno(status));

	/* not req_mod(), we need irqsave here! */
	spin_lock_irqsave(&device->resource->req_lock, flags);
	__req_mod(req, what, NULL, &m);
	spin_unlock_irqrestore(&device->resource->req_lock, flags);
	put_ldev(device);

	if (m.bio)
		complete_master_bio(device, &m);
}

void drbd_csum_pages(struct crypto_shash *tfm, struct page *page, void *digest)
/* kmap compat: KM_USER1 */
{
	SHASH_DESC_ON_STACK(desc, tfm);

	desc->tfm = tfm;

	crypto_shash_init(desc);

	page_chain_for_each(page) {
		unsigned off = page_chain_offset(page);
		unsigned len = page_chain_size(page);
		u8 *src;
		src = kmap_atomic(page);
		crypto_shash_update(desc, src + off, len);
		kunmap_atomic(src);
	}
	crypto_shash_final(desc, digest);
	shash_desc_zero(desc);
}

void drbd_csum_bio(struct crypto_shash *tfm, struct bio *bio, void *digest)
/* kmap compat: KM_USER1 */
{
	struct bio_vec bvec;
	struct bvec_iter iter;
	SHASH_DESC_ON_STACK(desc, tfm);

	desc->tfm = tfm;

	crypto_shash_init(desc);

	bio_for_each_segment(bvec, bio, iter) {
		u8 *src;
		src = kmap_atomic(bvec.bv_page);
		crypto_shash_update(desc, src + bvec.bv_offset, bvec.bv_len);
		kunmap_atomic(src);
		/* WRITE_SAME has only one segment,
		 * checksum the payload only once. */
		if (bio_op(bio) == REQ_OP_WRITE_SAME)
			break;
	}
	crypto_shash_final(desc, digest);
	shash_desc_zero(desc);
}

/* MAYBE merge common code with w_e_end_ov_req */
static int w_e_send_csum(struct drbd_work *w, int cancel)
{
	struct drbd_peer_request *peer_req = container_of(w, struct drbd_peer_request, w);
	struct drbd_peer_device *peer_device = peer_req->peer_device;
	int digest_size;
	void *digest;
	int err = 0;

	if (unlikely(cancel))
		goto out;

	if (unlikely((peer_req->flags & EE_WAS_ERROR) != 0))
		goto out;

	digest_size = crypto_shash_digestsize(peer_device->connection->csums_tfm);
	digest = drbd_prepare_drequest_csum(peer_req, digest_size);
	if (digest) {
		drbd_csum_pages(peer_device->connection->csums_tfm, peer_req->page_chain.head, digest);
		/* Free peer_req and pages before send.
		 * In case we block on congestion, we could otherwise run into
		 * some distributed deadlock, if the other side blocks on
		 * congestion as well, because our receiver blocks in
		 * drbd_alloc_pages due to pp_in_use > max_buffers. */
		drbd_free_peer_req(peer_req);
		peer_req = NULL;
		inc_rs_pending(peer_device);
		err = drbd_send_command(peer_device, P_CSUM_RS_REQUEST, DATA_STREAM);
	} else {
		drbd_err(peer_device, "kmalloc() of digest failed.\n");
		err = -ENOMEM;
	}

out:
	if (peer_req)
		drbd_free_peer_req(peer_req);

	if (unlikely(err))
		drbd_err(peer_device, "drbd_send_drequest(..., csum) failed\n");
	return err;
}

static int read_for_csum(struct drbd_peer_device *peer_device, sector_t sector, int size)
{
	struct drbd_device *device = peer_device->device;
	struct drbd_peer_request *peer_req;

	if (!get_ldev(device))
		return -EIO;

	/* Do not wait if no memory is immediately available.  */
	peer_req = drbd_alloc_peer_req(peer_device, GFP_TRY & ~__GFP_RECLAIM);
	if (!peer_req)
		goto defer;
	if (size) {
		drbd_alloc_page_chain(&peer_device->connection->transport,
			&peer_req->page_chain, DIV_ROUND_UP(size, PAGE_SIZE), GFP_TRY);
		if (!peer_req->page_chain.head)
			goto defer2;
	}
	peer_req->i.size = size;
	peer_req->i.sector = sector;
	peer_req->block_id = ID_SYNCER; /* unused */

	peer_req->w.cb = w_e_send_csum;
	peer_req->opf = REQ_OP_READ;
	spin_lock_irq(&device->resource->req_lock);
	list_add_tail(&peer_req->w.list, &peer_device->connection->read_ee);
	spin_unlock_irq(&device->resource->req_lock);

	atomic_add(size >> 9, &device->rs_sect_ev);
	if (drbd_submit_peer_request(peer_req) == 0)
		return 0;

	/* If it failed because of ENOMEM, retry should help.  If it failed
	 * because bio_add_page failed (probably broken lower level driver),
	 * retry may or may not help.
	 * If it does not, you may need to force disconnect. */
	spin_lock_irq(&device->resource->req_lock);
	list_del(&peer_req->w.list);
	spin_unlock_irq(&device->resource->req_lock);

defer2:
	drbd_free_peer_req(peer_req);
defer:
	put_ldev(device);
	return -EAGAIN;
}

int w_resync_timer(struct drbd_work *w, int cancel)
{
	struct drbd_peer_device *peer_device =
		container_of(w, struct drbd_peer_device, resync_work);

	if (test_bit(SYNC_TARGET_TO_BEHIND, &peer_device->flags))
		return 0;

	mutex_lock(&peer_device->resync_next_bit_mutex);
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
	mutex_unlock(&peer_device->resync_next_bit_mutex);

	return 0;
}

int w_send_uuids(struct drbd_work *w, int cancel)
{
	struct drbd_peer_device *peer_device =
		container_of(w, struct drbd_peer_device, propagate_uuids_work);

	if (peer_device->repl_state[NOW] < L_ESTABLISHED ||
	    !test_bit(INITIAL_STATE_SENT, &peer_device->flags))
		return 0;

	drbd_send_uuids(peer_device, 0, 0);

	return 0;
}

void resync_timer_fn(struct timer_list *t)
{
	struct drbd_peer_device *peer_device = from_timer(peer_device, t, resync_timer);

	if (test_bit(SYNC_TARGET_TO_BEHIND, &peer_device->flags))
		return;

	drbd_queue_work_if_unqueued(
		&peer_device->connection->sender_work,
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

struct fifo_buffer *fifo_alloc(unsigned int fifo_size)
{
	struct fifo_buffer *fb;

	fb = kzalloc(struct_size(fb, values, fifo_size), GFP_NOIO);
	if (!fb)
		return NULL;

	fb->head_index = 0;
	fb->size = fifo_size;
	fb->total = 0;

	return fb;
}

/* FIXME by choosing to calculate in nano seconds, we now have several do_div()
 * in here, which I find very ugly.
 */
static int drbd_rs_controller(struct drbd_peer_device *peer_device, u64 sect_in, u64 duration_ns)
{
	const u64 max_duration_ns = RS_MAKE_REQS_INTV_NS * 10;
	struct peer_device_conf *pdc;
	unsigned int want;     /* The number of sectors we want in-flight */
	int req_sect; /* Number of sectors to request in this turn */
	int correction; /* Number of sectors more we need in-flight */
	int cps; /* correction per invocation of drbd_rs_controller() */
	int steps; /* Number of time steps to plan ahead */
	int curr_corr;
	u64 max_sect;
	struct fifo_buffer *plan;
	u64 duration_ms;

	if (duration_ns == 0)
		duration_ns = 1;
	else if (duration_ns > max_duration_ns)
		duration_ns = max_duration_ns;

	/* Scale sect_in so that it represents the number of sectors which
	 * would have arrived if the cycle had lasted the normal time
	 * (RS_MAKE_REQS_INTV). */
	sect_in = sect_in * RS_MAKE_REQS_INTV_NS;
	do_div(sect_in, duration_ns);

	pdc = rcu_dereference(peer_device->conf);
	plan = rcu_dereference(peer_device->rs_plan_s);

	steps = plan->size; /* (pdc->c_plan_ahead * 10 * RS_MAKE_REQS_INTV) / HZ; */

	if (peer_device->rs_in_flight + sect_in == 0) { /* At start of resync */
		want = ((pdc->resync_rate * 2 * RS_MAKE_REQS_INTV) / HZ) * steps;
	} else { /* normal path */
		if (pdc->c_fill_target) {
			want = pdc->c_fill_target;
		} else {
			u64 tmp = sect_in * pdc->c_delay_target * NSEC_PER_SEC;
			do_div(tmp, (duration_ns * 10));
			want = tmp;
		}
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

	if (pdc->c_max_rate == 0) {
		/* No rate limiting. */
		max_sect = ~0ULL;
	} else {
		max_sect = (u64)pdc->c_max_rate * 2 * duration_ns;
		do_div(max_sect, NSEC_PER_SEC);
	}

	duration_ms = duration_ns;
	do_div(duration_ms, NSEC_PER_MSEC);
	dynamic_drbd_dbg(peer_device, "dur=%lluns (%llums) sect_in=%llu in_flight=%d wa=%u co=%d st=%d cps=%d cc=%d rs=%d mx=%llu\n",
		 duration_ns, duration_ms, sect_in, peer_device->rs_in_flight, want, correction,
		 steps, cps, curr_corr, req_sect, max_sect);

	if (req_sect > max_sect)
		req_sect = max_sect;

	return req_sect;
}

static int drbd_rs_number_requests(struct drbd_peer_device *peer_device)
{
	struct net_conf *nc;
	ktime_t duration, now;
	unsigned int sect_in;  /* Number of sectors that came in since the last turn */
	int number, mxb;

	sect_in = atomic_xchg(&peer_device->rs_sect_in, 0);
	peer_device->rs_in_flight -= sect_in;

	now = ktime_get();
	duration = ktime_sub(now, peer_device->rs_last_mk_req_kt);
	peer_device->rs_last_mk_req_kt = now;

	rcu_read_lock();
	nc = rcu_dereference(peer_device->connection->transport.net_conf);
	mxb = nc ? nc->max_buffers : 0;
	if (rcu_dereference(peer_device->rs_plan_s)->size) {
		number = drbd_rs_controller(peer_device, sect_in, ktime_to_ns(duration)) >> (BM_BLOCK_SHIFT - 9);
		peer_device->c_sync_rate = number * HZ * (BM_BLOCK_SIZE / 1024) / RS_MAKE_REQS_INTV;
	} else {
		peer_device->c_sync_rate = rcu_dereference(peer_device->conf)->resync_rate;
		number = RS_MAKE_REQS_INTV * peer_device->c_sync_rate  / ((BM_BLOCK_SIZE / 1024) * HZ);
	}
	rcu_read_unlock();

	/* Don't have more than "max-buffers"/2 in-flight.
	 * Otherwise we may cause the remote site to stall on drbd_alloc_pages(),
	 * potentially causing a distributed deadlock on congestion during
	 * online-verify or (checksum-based) resync, if max-buffers,
	 * socket buffer sizes and resync rate settings are mis-configured. */
	/* note that "number" is in units of "BM_BLOCK_SIZE" (which is 4k),
	 * mxb (as used here, and in drbd_alloc_pages on the peer) is
	 * "number of pages" (typically also 4k),
	 * but "rs_in_flight" is in "sectors" (512 Byte). */
	if (mxb - peer_device->rs_in_flight/8 < number)
		number = mxb - peer_device->rs_in_flight/8;

	return number;
}

static int drbd_resync_delay(struct drbd_peer_device *peer_device)
{
	struct peer_device_conf *pdc;
	unsigned long delay;

	if (peer_device->rs_in_flight > 0) {
		/* Requests in-flight. Use the standard delay. If all responses
		 * are received before this time, the resync work will be
		 * scheduled immediately. */
		return RS_MAKE_REQS_INTV;
	}

	rcu_read_lock();
	pdc = rcu_dereference(peer_device->conf);
	if (rcu_dereference(peer_device->rs_plan_s)->size) {
		if (pdc->c_max_rate == 0) {
			/* Dynamic resync with no rate limiting. This should
			 * not happen under normal circumstances. Use the
			 * standard delay. */
			delay = RS_MAKE_REQS_INTV;
		} else {
			/* Dynamic resync with rate limiting. This occurs when
			 * the peer responds so quickly to the resync requests
			 * that the rate limiting prevents any new requests
			 * from being made. Wait just long enough so that we
			 * can request some data next time. */
			delay = DIV_ROUND_UP((unsigned long)(HZ * BM_SECT_PER_BIT / 2), pdc->c_max_rate);
		}
	} else {
		/* Fixed resync rate. Use the standard delay. */
		delay = RS_MAKE_REQS_INTV;
	}
	rcu_read_unlock();

	return delay;
}

static int make_resync_request(struct drbd_peer_device *peer_device, int cancel)
{
	struct drbd_device *device = peer_device->device;
	struct drbd_transport *transport = &peer_device->connection->transport;
	unsigned long bit;
	sector_t sector;
	const sector_t capacity = get_capacity(device->vdisk);
	int max_bio_size;
	int number, rollback_i, size;
	int align;
	int i;
	int discard_granularity = 0;

	if (unlikely(cancel))
		return 0;

	if (peer_device->rs_total == 0) {
		/* empty resync? */
		drbd_resync_finished(peer_device, D_MASK);
		return 0;
	}

	if (test_bit(SYNC_TARGET_TO_BEHIND, &peer_device->flags)) {
		/* If a P_RS_CANCEL_AHEAD on control socket overtook the
		 * already queued data and state change to Ahead/Behind,
		 * don't add more resync requests, just wait it out. */
		if (drbd_ratelimit())
			drbd_info(peer_device, "peer pulled ahead during resync\n");
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

	if (peer_device->connection->agreed_features & DRBD_FF_THIN_RESYNC) {
		rcu_read_lock();
		discard_granularity = rcu_dereference(device->ldev->disk_conf)->rs_discard_granularity;
		rcu_read_unlock();
	}

	max_bio_size = queue_max_hw_sectors(device->rq_queue) << 9;
	number = drbd_rs_number_requests(peer_device);
	/* don't let rs_sectors_came_in() re-schedule us "early"
	 * just because the first reply came "fast", ... */
	peer_device->rs_in_flight += number * BM_SECT_PER_BIT;

	for (i = 0; i < number; i++) {
		bool send_buffer_ok = true;
		/* Stop generating RS requests, when half of the send buffer is filled */
		mutex_lock(&peer_device->connection->mutex[DATA_STREAM]);
		if (transport->ops->stream_ok(transport, DATA_STREAM)) {
			struct drbd_transport_stats transport_stats;
			int queued, sndbuf;

			transport->ops->stats(transport, &transport_stats);
			queued = transport_stats.send_buffer_used;
			sndbuf = transport_stats.send_buffer_size;
			if (queued > sndbuf / 2) {
				send_buffer_ok = false;
				transport->ops->hint(transport, DATA_STREAM, NOSPACE);
			}
		} else
			send_buffer_ok = false;
		mutex_unlock(&peer_device->connection->mutex[DATA_STREAM]);
		if (!send_buffer_ok)
			goto request_done;

next_sector:
		size = BM_BLOCK_SIZE;
		bit  = drbd_bm_find_next(peer_device, peer_device->resync_next_bit);

		if (bit == DRBD_END_OF_BITMAP) {
			peer_device->resync_next_bit = drbd_bm_bits(device);
			goto request_done;
		}

		sector = BM_BIT_TO_SECT(bit);

		if (drbd_try_rs_begin_io(peer_device, sector, true)) {
			peer_device->resync_next_bit = bit;
			goto request_done;
		}

		if (unlikely(drbd_bm_test_bit(peer_device, bit) == 0)) {
			peer_device->resync_next_bit = bit + 1;
			drbd_rs_complete_io(peer_device, sector);
			goto next_sector;
		}

		/* try to find some adjacent bits.
		 * we stop if we have already the maximum req size.
		 *
		 * Additionally always align bigger requests, in order to
		 * be prepared for all stripe sizes of software RAIDs.
		 */
		align = 1;
		rollback_i = i;
		while (i + 1 < number) {
			if (size + BM_BLOCK_SIZE > max_bio_size)
				break;

			/* Be always aligned */
			if (sector & ((1<<(align+3))-1))
				break;

			if (discard_granularity && size == discard_granularity)
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
		/* set the offset to start the next drbd_bm_find_next from */
		peer_device->resync_next_bit = bit + 1;

		/* adjust very last sectors, in case we are oddly sized */
		if (sector + (size>>9) > capacity)
			size = (capacity-sector)<<9;

		if (peer_device->use_csums) {
			switch (read_for_csum(peer_device, sector, size)) {
			case -EIO: /* Disk failure */
				put_ldev(device);
				return -EIO;
			case -EAGAIN: /* allocation failed, or ldev busy */
				drbd_rs_complete_io(peer_device, sector);
				peer_device->resync_next_bit = BM_SECT_TO_BIT(sector);
				i = rollback_i;
				goto request_done;
			case 0:
				/* everything ok */
				break;
			default:
				BUG();
			}
		} else {
			int err;

			inc_rs_pending(peer_device);
			err = drbd_send_drequest(peer_device,
						 size == discard_granularity ? P_RS_THIN_REQ : P_RS_DATA_REQUEST,
						 sector, size, ID_SYNCER);
			if (err) {
				drbd_err(device, "drbd_send_drequest() failed, aborting...\n");
				dec_rs_pending(peer_device);
				put_ldev(device);
				return err;
			}
		}
	}

request_done:
	/* ... but do a correction, in case we had to break/goto request_done; */
	peer_device->rs_in_flight -= (number - i) * BM_SECT_PER_BIT;

	if (peer_device->resync_next_bit >= drbd_bm_bits(device)) {
		/* last syncer _request_ was sent,
		 * but the P_RS_DATA_REPLY not yet received.  sync will end (and
		 * next sync group will resume), as soon as we receive the last
		 * resync data block, and the last bit is cleared.
		 * until then resync "work" is "inactive" ...
		 */
		put_ldev(device);
		return 0;
	}

	/* and in case that raced with the receiver, reschedule ourselves right now */
	if (i > 0 && atomic_read(&peer_device->rs_sect_in) >= peer_device->rs_in_flight) {
		drbd_queue_work_if_unqueued(
			&peer_device->connection->sender_work,
			&peer_device->resync_work);
	} else {
		mod_timer(&peer_device->resync_timer, jiffies + drbd_resync_delay(peer_device));
	}
	put_ldev(device);
	return 0;
}

static int make_ov_request(struct drbd_peer_device *peer_device, int cancel)
{
	struct drbd_device *device = peer_device->device;
	int number, i, size;
	sector_t sector;
	const sector_t capacity = get_capacity(device->vdisk);
	bool stop_sector_reached = false;

	if (unlikely(cancel))
		return 1;

	number = drbd_rs_number_requests(peer_device);
	sector = peer_device->ov_position;

	/* don't let rs_sectors_came_in() re-schedule us "early"
	 * just because the first reply came "fast", ... */
	peer_device->rs_in_flight += number * BM_SECT_PER_BIT;
	for (i = 0; i < number; i++) {
		if (sector >= capacity)
			break;

		/* We check for "finished" only in the reply path:
		 * w_e_end_ov_reply().
		 * We need to send at least one request out. */
		stop_sector_reached = i > 0
			&& verify_can_do_stop_sector(peer_device)
			&& sector >= peer_device->ov_stop_sector;
		if (stop_sector_reached)
			break;

		size = BM_BLOCK_SIZE;

		if (drbd_try_rs_begin_io(peer_device, sector, true))
			break;

		if (sector + (size>>9) > capacity)
			size = (capacity-sector)<<9;

		inc_rs_pending(peer_device);
		if (drbd_send_ov_request(peer_device, sector, size)) {
			dec_rs_pending(peer_device);
			return 0;
		}
		sector += BM_SECT_PER_BIT;
	}
	/* ... but do a correction, in case we had to break; ... */
	peer_device->rs_in_flight -= (number-i) * BM_SECT_PER_BIT;
	peer_device->ov_position = sector;
	if (stop_sector_reached)
		return 1;
	/* ... and in case that raced with the receiver,
	 * reschedule ourselves right now */
	if (i > 0 && atomic_read(&peer_device->rs_sect_in) >= peer_device->rs_in_flight)
		drbd_queue_work_if_unqueued(
			&peer_device->connection->sender_work,
			&peer_device->resync_work);
	if (i == 0)
		mod_timer(&peer_device->resync_timer, jiffies + RS_MAKE_REQS_INTV);
	return 1;
}

struct resync_finished_work {
	struct drbd_peer_device_work pdw;
	enum drbd_disk_state new_peer_disk_state;
};

static int w_resync_finished(struct drbd_work *w, int cancel)
{
	struct resync_finished_work *rfw = container_of(
		container_of(w, struct drbd_peer_device_work, w),
		struct resync_finished_work, pdw);

	drbd_resync_finished(rfw->pdw.peer_device, rfw->new_peer_disk_state);
	kfree(rfw);

	return 0;
}

void drbd_ping_peer(struct drbd_connection *connection)
{
	clear_bit(GOT_PING_ACK, &connection->flags);
	request_ping(connection);
	wait_event(connection->resource->state_wait,
		   test_bit(GOT_PING_ACK, &connection->flags) ||
		   connection->cstate[NOW] < C_CONNECTED);
}

/* caller needs to hold rcu_read_lock, req_lock, adm_mutex or conf_update */
struct drbd_peer_device *peer_device_by_node_id(struct drbd_device *device, int node_id)
{
	struct drbd_peer_device *peer_device;

	for_each_peer_device_rcu(peer_device, device) {
		if (peer_device->node_id == node_id)
			return peer_device;
	}

	return NULL;
}

static void __outdate_peer_disk_by_mask(struct drbd_device *device, u64 nodes)
{
	struct drbd_peer_device *peer_device;
	int node_id;

	for (node_id = 0; node_id < DRBD_NODE_ID_MAX; node_id++) {
		if (!(nodes & NODE_MASK(node_id)))
			continue;
		peer_device = peer_device_by_node_id(device, node_id);
		if (peer_device && peer_device->disk_state[NEW] >= D_CONSISTENT)
			__change_peer_disk_state(peer_device, D_OUTDATED);
	}
}

/* An annoying corner case is if we are resync target towards a bunch
   of nodes. One of the resyncs finished as STABLE_RESYNC, the others
   as UNSTABLE_RESYNC. */
static bool was_resync_stable(struct drbd_peer_device *peer_device)
{
	struct drbd_device *device = peer_device->device;

	if (test_bit(UNSTABLE_RESYNC, &peer_device->flags) &&
	    !test_bit(STABLE_RESYNC, &device->flags))
		return false;

	set_bit(STABLE_RESYNC, &device->flags);
	/* that STABLE_RESYNC bit gets reset if in any other ongoing resync
	   we receive something from a resync source that is marked with
	   UNSTABLE RESYNC. */

	return true;
}

static u64 __cancel_other_resyncs(struct drbd_device *device)
{
	struct drbd_peer_device *peer_device;
	u64 target_m = 0;

	for_each_peer_device(peer_device, device) {
		if (peer_device->repl_state[NEW] == L_PAUSED_SYNC_T) {
			target_m |= NODE_MASK(peer_device->node_id);
			__change_repl_state(peer_device, L_ESTABLISHED);
		}
	}

	return target_m;
}

static void resync_again(struct drbd_device *device, u64 source_m, u64 target_m)
{
	struct drbd_peer_device *peer_device;

	for_each_peer_device(peer_device, device) {
		if (peer_device->resync_again) {
			u64 m = NODE_MASK(peer_device->node_id);
			enum drbd_repl_state new_repl_state =
				source_m & m ? L_WF_BITMAP_S :
				target_m & m ? L_WF_BITMAP_T :
				L_ESTABLISHED;

			if (new_repl_state != L_ESTABLISHED) {
				peer_device->resync_again--;
				begin_state_change_locked(device->resource, CS_VERBOSE);
				__change_repl_state(peer_device, new_repl_state);
				end_state_change_locked(device->resource);
			}
		}
	}
}

static void init_resync_stable_bits(struct drbd_peer_device *first_target_pd)
{
	struct drbd_device *device = first_target_pd->device;
	struct drbd_peer_device *peer_device;

	clear_bit(UNSTABLE_RESYNC, &first_target_pd->flags);

	/* Clear the device wide STABLE_RESYNC flag when becoming
	   resync target on the first peer_device. */
	for_each_peer_device(peer_device, device) {
		enum drbd_repl_state repl_state = peer_device->repl_state[NOW];
		if (peer_device == first_target_pd)
			continue;
		if (repl_state == L_SYNC_TARGET || repl_state == L_PAUSED_SYNC_T)
			return;
	}
	clear_bit(STABLE_RESYNC, &device->flags);
}

static void after_reconciliation_resync(struct drbd_connection *connection)
{
	struct drbd_connection *lost_peer =
		drbd_get_connection_by_node_id(connection->resource,
					       connection->after_reconciliation.lost_node_id);

	if (lost_peer) {
		if (lost_peer->cstate[NOW] < C_CONNECTED)
			lost_peer->last_dagtag_sector =
				connection->after_reconciliation.dagtag_sector;

		kref_put(&lost_peer->kref, drbd_destroy_connection);
	}

	connection->after_reconciliation.lost_node_id = -1;
}

static void try_to_get_resynced_from_primary(struct drbd_device *device)
{
	struct drbd_resource *resource = device->resource;
	struct drbd_peer_device *peer_device;
	struct drbd_connection *connection;

	spin_lock_irq(&resource->req_lock);
	for_each_peer_device(peer_device, device) {
		if (peer_device->connection->peer_role[NEW] == R_PRIMARY &&
		    peer_device->disk_state[NEW] == D_UP_TO_DATE)
			goto found;
	}
	peer_device = NULL;
found:
	spin_unlock_irq(&resource->req_lock);

	if (!peer_device)
		return;

	connection = peer_device->connection;
	if (connection->agreed_pro_version < 118) {
		drbd_warn(connection,
			  "peer is lower than protocol vers 118, reconnecting to get resynced\n");
		change_cstate(connection, C_PROTOCOL_ERROR, CS_HARD);
		return;
	}

	drbd_send_uuids(peer_device, 0, 0);
	drbd_start_resync(peer_device, L_SYNC_TARGET);
}

int drbd_resync_finished(struct drbd_peer_device *peer_device,
			 enum drbd_disk_state new_peer_disk_state)
{
	struct drbd_device *device = peer_device->device;
	struct drbd_connection *connection = peer_device->connection;
	enum drbd_repl_state *repl_state = peer_device->repl_state;
	enum drbd_repl_state old_repl_state = L_ESTABLISHED;
	bool try_to_get_resynced_from_primary_flag = false;
	u64 source_m = 0, target_m = 0;
	unsigned long db, dt, dbdt;
	unsigned long n_oos;
	char *khelper_cmd = NULL;
	int verify_done = 0;
	bool aborted = false;


	if (repl_state[NOW] == L_SYNC_SOURCE || repl_state[NOW] == L_PAUSED_SYNC_S) {
		/* Make sure all queued w_update_peers()/consider_sending_peers_in_sync()
		   executed before killing the resync_lru with drbd_rs_del_all() */
		if (current == device->resource->worker.task)
			goto queue_on_sender_workq;
		else
			drbd_flush_workqueue(&device->resource->work);
	}

	/* Remove all elements from the resync LRU. Since future actions
	 * might set bits in the (main) bitmap, then the entries in the
	 * resync LRU would be wrong. */
	if (drbd_rs_del_all(peer_device)) {
		struct resync_finished_work *rfw;

		/* In case this is not possible now, most probably because
		 * there are P_RS_DATA_REPLY Packets lingering on the sender's
		 * queue (or even the read operations for those packets
		 * is not finished by now).   Retry in 100ms. */

		schedule_timeout_interruptible(HZ / 10);
	queue_on_sender_workq:
		rfw = kmalloc(sizeof(*rfw), GFP_ATOMIC);
		if (rfw) {
			rfw->pdw.w.cb = w_resync_finished;
			rfw->pdw.peer_device = peer_device;
			rfw->new_peer_disk_state = new_peer_disk_state;
			drbd_queue_work(&connection->sender_work, &rfw->pdw.w);
			return 1;
		}
		drbd_err(peer_device, "Warn failed to kmalloc(dw).\n");
	}

	dt = (jiffies - peer_device->rs_start - peer_device->rs_paused) / HZ;
	if (dt <= 0)
		dt = 1;
	db = peer_device->rs_total;
	/* adjust for verify start and stop sectors, respective reached position */
	if (repl_state[NOW] == L_VERIFY_S || repl_state[NOW] == L_VERIFY_T)
		db -= peer_device->ov_left;

	dbdt = Bit2KB(db/dt);
	peer_device->rs_paused /= HZ;

	if (!get_ldev(device))
		goto out;

	drbd_ping_peer(connection);

	down_write(&device->uuid_sem);
	spin_lock_irq(&device->resource->req_lock);
	begin_state_change_locked(device->resource, CS_VERBOSE);
	old_repl_state = repl_state[NOW];

	verify_done = (repl_state[NOW] == L_VERIFY_S || repl_state[NOW] == L_VERIFY_T);

	/* This protects us against multiple calls (that can happen in the presence
	   of application IO), and against connectivity loss just before we arrive here. */
	if (peer_device->repl_state[NOW] <= L_ESTABLISHED)
		goto out_unlock;
	__change_repl_state(peer_device, L_ESTABLISHED);

	aborted = device->disk_state[NOW] == D_OUTDATED && new_peer_disk_state == D_INCONSISTENT;
	{
	char tmp[sizeof(" but 01234567890123456789 4k blocks skipped")] = "";
	if (verify_done && peer_device->ov_skipped)
		snprintf(tmp, sizeof(tmp), " but %lu %dk blocks skipped",
			peer_device->ov_skipped, Bit2KB(1));
	drbd_info(peer_device, "%s %s%s (total %lu sec; paused %lu sec; %lu K/sec)\n",
		  verify_done ? "Online verify" : "Resync",
		  aborted ? "aborted" : "done", tmp,
		  dt + peer_device->rs_paused, peer_device->rs_paused, dbdt);
	}

	n_oos = drbd_bm_total_weight(peer_device);

	if (repl_state[NOW] == L_VERIFY_S || repl_state[NOW] == L_VERIFY_T) {
		if (n_oos) {
			drbd_alert(peer_device, "Online verify found %lu %dk blocks out of sync!\n",
			      n_oos, Bit2KB(1));
			khelper_cmd = "out-of-sync";
		}
	} else {
		if (!aborted && (n_oos - peer_device->rs_failed != 0)) {
			drbd_warn(peer_device, "expected n_oos:%lu to be equal to rs_failed:%lu\n",
				n_oos, peer_device->rs_failed);
		}

		if (repl_state[NOW] == L_SYNC_TARGET || repl_state[NOW] == L_PAUSED_SYNC_T)
			khelper_cmd = "after-resync-target";

		if (peer_device->use_csums && peer_device->rs_total) {
			const unsigned long s = peer_device->rs_same_csum;
			const unsigned long t = peer_device->rs_total;
			const int ratio =
				(t == 0)     ? 0 :
			(t < 100000) ? ((s*100)/t) : (s/(t/100));
			drbd_info(peer_device, "%u %% had equal checksums, eliminated: %luK; "
			     "transferred %luK total %luK\n",
			     ratio,
			     Bit2KB(peer_device->rs_same_csum),
			     Bit2KB(peer_device->rs_total - peer_device->rs_same_csum),
			     Bit2KB(peer_device->rs_total));
		}
	}

	if (peer_device->rs_failed) {
		drbd_info(peer_device, "            %lu failed blocks\n", peer_device->rs_failed);

		if (repl_state[NOW] == L_SYNC_TARGET || repl_state[NOW] == L_PAUSED_SYNC_T) {
			__change_disk_state(device, D_INCONSISTENT);
			__change_peer_disk_state(peer_device, D_UP_TO_DATE);
		} else {
			__change_disk_state(device, D_UP_TO_DATE);
			__change_peer_disk_state(peer_device, D_INCONSISTENT);
		}
	} else {
		if (repl_state[NOW] == L_SYNC_TARGET || repl_state[NOW] == L_PAUSED_SYNC_T) {
			bool stable_resync = was_resync_stable(peer_device);
			if (stable_resync) {
				enum drbd_disk_state new_disk_state = peer_device->disk_state[NOW];
				if (new_disk_state < D_UP_TO_DATE &&
				    test_bit(SYNC_SRC_CRASHED_PRI, &peer_device->flags)) {
					try_to_get_resynced_from_primary_flag = true;
					set_bit(CRASHED_PRIMARY, &device->flags);
				}
				__change_disk_state(device, new_disk_state);
			}

			if (device->disk_state[NEW] == D_UP_TO_DATE)
				target_m = __cancel_other_resyncs(device);

			if (stable_resync && peer_device->uuids_received) {
				const int node_id = device->resource->res_opts.node_id;
				int i;

				u64 newer = drbd_uuid_resync_finished(peer_device);
				__outdate_peer_disk_by_mask(device, newer);
				drbd_print_uuids(peer_device, "updated UUIDs");

				/* Now the two UUID sets are equal, update what we
				 * know of the peer. */
				peer_device->current_uuid = drbd_current_uuid(device);
				peer_device->bitmap_uuids[node_id] = drbd_bitmap_uuid(peer_device);
				for (i = 0; i < ARRAY_SIZE(peer_device->history_uuids); i++)
					peer_device->history_uuids[i] =
						drbd_history_uuid(device, i);
			} else {
				if (!peer_device->uuids_received)
					drbd_err(peer_device, "BUG: uuids were not received!\n");

				if (test_bit(UNSTABLE_RESYNC, &peer_device->flags))
					drbd_info(peer_device, "Peer was unstable during resync\n");
			}
		} else if (repl_state[NOW] == L_SYNC_SOURCE || repl_state[NOW] == L_PAUSED_SYNC_S) {
			if (new_peer_disk_state != D_MASK)
				__change_peer_disk_state(peer_device, new_peer_disk_state);
			if (connection->agreed_pro_version < 110) {
				drbd_uuid_set_bitmap(peer_device, 0UL);
				drbd_print_uuids(peer_device, "updated UUIDs");
			}
		}
	}

out_unlock:
	end_state_change_locked(device->resource);

	put_ldev(device);

	peer_device->rs_total  = 0;
	peer_device->rs_failed = 0;
	peer_device->rs_paused = 0;

	if (old_repl_state == L_SYNC_TARGET || old_repl_state == L_PAUSED_SYNC_T)
		target_m |= NODE_MASK(peer_device->node_id);
	else if (old_repl_state == L_SYNC_SOURCE || old_repl_state == L_PAUSED_SYNC_S)
		source_m |= NODE_MASK(peer_device->node_id);

	resync_again(device, source_m, target_m);
	spin_unlock_irq(&device->resource->req_lock);
	up_write(&device->uuid_sem);
	if (connection->after_reconciliation.lost_node_id != -1)
		after_reconciliation_resync(connection);

out:
	/* reset start sector, if we reached end of device */
	if (verify_done && peer_device->ov_left == 0)
		peer_device->ov_start_sector = 0;

	drbd_md_sync_if_dirty(device);

	if (khelper_cmd)
		drbd_maybe_khelper(device, connection, khelper_cmd);

	/* If we have been sync source, and have an effective fencing-policy,
	 * once *all* volumes are back in sync, call "unfence". */
	if (old_repl_state == L_SYNC_SOURCE || old_repl_state == L_PAUSED_SYNC_S) {
		enum drbd_disk_state disk_state = D_MASK;
		enum drbd_disk_state pdsk_state = D_MASK;
		enum drbd_fencing_policy fencing_policy = FP_DONT_CARE;

		rcu_read_lock();
		fencing_policy = connection->fencing_policy;
		if (fencing_policy != FP_DONT_CARE) {
			struct drbd_peer_device *peer_device;
			int vnr;
			idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
				struct drbd_device *device = peer_device->device;
				disk_state = min_t(enum drbd_disk_state, disk_state, device->disk_state[NOW]);
				pdsk_state = min_t(enum drbd_disk_state, pdsk_state, peer_device->disk_state[NOW]);
			}
		}
		rcu_read_unlock();
		if (disk_state == D_UP_TO_DATE && pdsk_state == D_UP_TO_DATE)
			drbd_maybe_khelper(NULL, connection, "unfence-peer");
	}

	if (try_to_get_resynced_from_primary_flag)
		try_to_get_resynced_from_primary(device);

	return 1;
}

/* helper */
static void move_to_net_ee_or_free(struct drbd_connection *connection, struct drbd_peer_request *peer_req)
{
	if (drbd_peer_req_has_active_page(peer_req)) {
		/* This might happen if sendpage() has not finished */
		struct drbd_resource *resource = connection->resource;
		int i = DIV_ROUND_UP(peer_req->i.size, PAGE_SIZE);
		atomic_add(i, &connection->pp_in_use_by_net);
		atomic_sub(i, &connection->pp_in_use);
		spin_lock_irq(&resource->req_lock);
		list_add_tail(&peer_req->w.list, &peer_req->peer_device->connection->net_ee);
		spin_unlock_irq(&resource->req_lock);
		wake_up(&resource->pp_wait);
	} else
		drbd_free_peer_req(peer_req);
}

/**
 * w_e_end_data_req() - Worker callback, to send a P_DATA_REPLY packet in response to a P_DATA_REQUEST
 * @w:		work object.
 * @cancel:	The connection will be closed anyways
 */
int w_e_end_data_req(struct drbd_work *w, int cancel)
{
	struct drbd_peer_request *peer_req = container_of(w, struct drbd_peer_request, w);
	struct drbd_peer_device *peer_device = peer_req->peer_device;
	int err;

	if (unlikely(cancel)) {
		drbd_free_peer_req(peer_req);
		dec_unacked(peer_device);
		return 0;
	}

	if (likely((peer_req->flags & EE_WAS_ERROR) == 0)) {
		err = drbd_send_block(peer_device, P_DATA_REPLY, peer_req);
	} else {
		if (drbd_ratelimit())
			drbd_err(peer_device, "Sending NegDReply. sector=%llus.\n",
			    (unsigned long long)peer_req->i.sector);

		err = drbd_send_ack(peer_device, P_NEG_DREPLY, peer_req);
	}

	dec_unacked(peer_device);

	move_to_net_ee_or_free(peer_device->connection, peer_req);

	if (unlikely(err))
		drbd_err(peer_device, "drbd_send_block() failed\n");
	return err;
}

static bool all_zero(struct drbd_peer_request *peer_req)
/* kmap compat: KM_USER1 */
{
	struct page *page = peer_req->page_chain.head;
	unsigned int len = peer_req->i.size;

	page_chain_for_each(page) {
		unsigned int l = min_t(unsigned int, len, PAGE_SIZE);
		unsigned int i, words = l / sizeof(long);
		unsigned long *d;

		d = kmap_atomic(page);
		for (i = 0; i < words; i++) {
			if (d[i]) {
				kunmap_atomic(d);
				return false;
			}
		}
		kunmap_atomic(d);
		len -= l;
	}

	return true;
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
	struct drbd_connection *connection = peer_device->connection;
	struct drbd_device *device = peer_device->device;
	int err;

	if (unlikely(cancel)) {
		drbd_free_peer_req(peer_req);
		dec_unacked(peer_device);
		return 0;
	}

	if (get_ldev_if_state(device, D_DETACHING)) {
		drbd_rs_complete_io(peer_device, peer_req->i.sector);
		put_ldev(device);
	}

	if (peer_device->repl_state[NOW] == L_AHEAD) {
		err = drbd_send_ack(peer_device, P_RS_CANCEL, peer_req);
	} else if (likely((peer_req->flags & EE_WAS_ERROR) == 0)) {
		if (likely(peer_device->disk_state[NOW] >= D_INCONSISTENT)) {
			inc_rs_pending(peer_device);
			/* If we send back as P_RS_DATA_REPLY,
			 * this is overestimating "in-flight" accounting.
			 * But needed to be properly balanced with
			 * the atomic_sub() in got_BlockAck.
			 * TODO: to fix that, we'd need a protocol bump. */
			atomic_add(peer_req->i.size >> 9, &connection->rs_in_flight);
			if (peer_req->flags & EE_RS_THIN_REQ && all_zero(peer_req)) {
				err = drbd_send_rs_deallocated(peer_device, peer_req);
			} else {
				err = drbd_send_block(peer_device, P_RS_DATA_REPLY, peer_req);
			}
		} else {
			if (drbd_ratelimit())
				drbd_err(peer_device, "Not sending RSDataReply, "
				    "partner DISKLESS!\n");
			err = 0;
		}
	} else {
		if (drbd_ratelimit())
			drbd_err(peer_device, "Sending NegRSDReply. sector %llus.\n",
			    (unsigned long long)peer_req->i.sector);

		err = drbd_send_ack(peer_device, P_NEG_RS_DREPLY, peer_req);

		/* update resync data with failure */
		drbd_rs_failed_io(peer_device, peer_req->i.sector, peer_req->i.size);
	}

	dec_unacked(peer_device);

	move_to_net_ee_or_free(peer_device->connection, peer_req);

	if (unlikely(err))
		drbd_err(peer_device, "drbd_send_block() failed\n");
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
		drbd_free_peer_req(peer_req);
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
			digest_size = crypto_shash_digestsize(peer_device->connection->csums_tfm);
			D_ASSERT(device, digest_size == di->digest_size);
			digest = kmalloc(digest_size, GFP_NOIO);
			if (digest) {
				drbd_csum_pages(peer_device->connection->csums_tfm, peer_req->page_chain.head, digest);
				eq = !memcmp(digest, di->digest, digest_size);
				kfree(digest);
			}
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
			atomic_add(peer_req->i.size >> 9, &peer_device->connection->rs_in_flight);
			err = drbd_send_block(peer_device, P_RS_DATA_REPLY, peer_req);
		}
	} else {
		err = drbd_send_ack(peer_device, P_NEG_RS_DREPLY, peer_req);
		if (drbd_ratelimit())
			drbd_err(device, "Sending NegDReply. I guess it gets messy.\n");
	}

	dec_unacked(peer_device);
	move_to_net_ee_or_free(peer_device->connection, peer_req);

	if (unlikely(err))
		drbd_err(device, "drbd_send_block/ack() failed\n");
	return err;
}

int w_e_end_ov_req(struct drbd_work *w, int cancel)
{
	struct drbd_peer_request *peer_req = container_of(w, struct drbd_peer_request, w);
	struct drbd_peer_device *peer_device = peer_req->peer_device;
	int digest_size;
	void *digest;
	int err = 0;

	if (unlikely(cancel))
		goto out;

	digest_size = crypto_shash_digestsize(peer_device->connection->verify_tfm);
	/* FIXME if this allocation fails, online verify will not terminate! */
	digest = drbd_prepare_drequest_csum(peer_req, digest_size);
	if (!digest) {
		err = -ENOMEM;
		goto out;
	}

	if (!(peer_req->flags & EE_WAS_ERROR))
		drbd_csum_pages(peer_device->connection->verify_tfm, peer_req->page_chain.head, digest);
	else
		memset(digest, 0, digest_size);

	/* Free peer_req and pages before send.
	 * In case we block on congestion, we could otherwise run into
	 * some distributed deadlock, if the other side blocks on
	 * congestion as well, because our receiver blocks in
	 * drbd_alloc_pages due to pp_in_use > max_buffers. */
	drbd_free_peer_req(peer_req);
	peer_req = NULL;

	inc_rs_pending(peer_device);
	err = drbd_send_command(peer_device, P_OV_REPLY, DATA_STREAM);
	if (err)
		dec_rs_pending(peer_device);

out:
	if (peer_req)
		drbd_free_peer_req(peer_req);
	dec_unacked(peer_device);
	return err;
}

void drbd_ov_out_of_sync_found(struct drbd_peer_device *peer_device, sector_t sector, int size)
{
	if (peer_device->ov_last_oos_start + peer_device->ov_last_oos_size == sector) {
		peer_device->ov_last_oos_size += size>>9;
	} else {
		ov_out_of_sync_print(peer_device);
		peer_device->ov_last_oos_start = sector;
		peer_device->ov_last_oos_size = size>>9;
	}
	drbd_set_out_of_sync(peer_device, sector, size);
}

void verify_progress(struct drbd_peer_device *peer_device,
		const sector_t sector, const unsigned int size)
{
	bool stop_sector_reached =
		(peer_device->repl_state[NOW] == L_VERIFY_S) &&
		verify_can_do_stop_sector(peer_device) &&
		(sector + (size>>9)) >= peer_device->ov_stop_sector;

	--peer_device->ov_left;

	/* let's advance progress step marks only for every other megabyte */
	if ((peer_device->ov_left & 0x1ff) == 0)
		drbd_advance_rs_marks(peer_device, peer_device->ov_left);

	if (peer_device->ov_left == 0 || stop_sector_reached)
		drbd_peer_device_post_work(peer_device, RS_DONE);
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
		drbd_free_peer_req(peer_req);
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
		digest_size = crypto_shash_digestsize(peer_device->connection->verify_tfm);
		digest = kmalloc(digest_size, GFP_NOIO);
		if (digest) {
			drbd_csum_pages(peer_device->connection->verify_tfm, peer_req->page_chain.head, digest);

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
	drbd_free_peer_req(peer_req);
	if (!eq)
		drbd_ov_out_of_sync_found(peer_device, sector, size);
	else
		ov_out_of_sync_print(peer_device);

	err = drbd_send_ack_ex(peer_device, P_OV_RESULT, sector, size,
			       eq ? ID_IN_SYNC : ID_OUT_OF_SYNC);

	dec_unacked(peer_device);

	verify_progress(peer_device, sector, size);

	return err;
}

/* FIXME
 * We need to track the number of pending barrier acks,
 * and to be able to wait for them.
 * See also comment in drbd_adm_attach before drbd_suspend_io.
 */
static int drbd_send_barrier(struct drbd_connection *connection)
{
	struct p_barrier *p;
	int err;

	p = conn_prepare_command(connection, sizeof(*p), DATA_STREAM);
	if (!p)
		return -EIO;

	p->barrier = connection->send.current_epoch_nr;
	p->pad = 0;
	connection->send.last_sent_epoch_nr = connection->send.current_epoch_nr;
	connection->send.current_epoch_writes = 0;
	connection->send.last_sent_barrier_jif = jiffies;

	set_bit(BARRIER_ACK_PENDING, &connection->flags);
	err = send_command(connection, -1, P_BARRIER, DATA_STREAM);
	if (err) {
		clear_bit(BARRIER_ACK_PENDING, &connection->flags);
		wake_up(&connection->resource->barrier_wait);
	}
	return err;
}

static bool need_unplug(struct drbd_connection *connection)
{
	unsigned i = connection->todo.unplug_slot;
	return dagtag_newer_eq(connection->send.current_dagtag_sector,
			connection->todo.unplug_dagtag_sector[i]);
}

static void maybe_send_unplug_remote(struct drbd_connection *connection, bool send_anyways)
{
	if (need_unplug(connection)) {
		/* Yes, this is non-atomic wrt. its use in drbd_unplug_fn.
		 * We save a spin_lock_irq, and worst case
		 * we occasionally miss an unplug event. */

		/* Paranoia: to avoid a continuous stream of unplug-hints,
		 * in case we never get any unplug events */
		connection->todo.unplug_dagtag_sector[connection->todo.unplug_slot] =
			connection->send.current_dagtag_sector + (1ULL << 63);
		/* advance the current unplug slot */
		connection->todo.unplug_slot ^= 1;
	} else if (!send_anyways)
		return;

	if (connection->cstate[NOW] < C_CONNECTED)
		return;

	if (!conn_prepare_command(connection, 0, DATA_STREAM))
		return;

	send_command(connection, -1, P_UNPLUG_REMOTE, DATA_STREAM);
}

static bool __drbd_may_sync_now(struct drbd_peer_device *peer_device)
{
	struct drbd_device *other_device = peer_device->device;
	int ret = true;

	rcu_read_lock();
	while (1) {
		struct drbd_peer_device *other_peer_device;
		int resync_after;

		if (!other_device->ldev || other_device->disk_state[NOW] == D_DISKLESS)
			break;
		resync_after = rcu_dereference(other_device->ldev->disk_conf)->resync_after;
		if (resync_after == -1)
			break;
		other_device = minor_to_device(resync_after);
		if (!other_device)
			break;
		for_each_peer_device_rcu(other_peer_device, other_device) {
			if ((other_peer_device->repl_state[NOW] >= L_SYNC_SOURCE &&
			     other_peer_device->repl_state[NOW] <= L_PAUSED_SYNC_T) ||
			    other_peer_device->resync_susp_dependency[NOW] ||
			    other_peer_device->resync_susp_peer[NOW] ||
			    other_peer_device->resync_susp_user[NOW]) {
				ret = false;
				goto break_unlock;
			}
		}
	}
break_unlock:
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

	/* FIXME seriously inefficient with many devices,
	 * while also ignoring the input "device" argument :-( */
	rcu_read_lock();
	idr_for_each_entry(&drbd_devices, other_device, vnr) {
		struct drbd_peer_device *other_peer_device;

		begin_state_change_locked(other_device->resource, CS_HARD);
		if (other_device->disk_state[NOW] == D_DISKLESS) {
			abort_state_change_locked(other_device->resource);
			continue;
		}
		for_each_peer_device_rcu(other_peer_device, other_device) {
			if (other_peer_device->repl_state[NOW] == L_OFF)
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

	/* FIXME seriously inefficient with many devices,
	 * while also ignoring the input "device" argument :-( */
	rcu_read_lock();
	idr_for_each_entry(&drbd_devices, other_device, vnr) {
		struct drbd_peer_device *other_peer_device;

		begin_state_change_locked(other_device->resource, CS_HARD);
		if (other_device->disk_state[NOW] == D_DISKLESS) {
			abort_state_change_locked(other_device->resource);
			continue;
		}
		for_each_peer_device_rcu(other_peer_device, other_device) {
			if (other_peer_device->repl_state[NOW] == L_OFF)
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

/* caller must hold resources_mutex */
enum drbd_ret_code drbd_resync_after_valid(struct drbd_device *device, int resync_after)
{
	struct drbd_device *other_device;
	int rv = NO_ERROR;

	if (resync_after == -1)
		return NO_ERROR;
	if (resync_after < -1)
		return ERR_RESYNC_AFTER;
	other_device = minor_to_device(resync_after);

	/* You are free to depend on diskless, non-existing,
	 * or not yet/no longer existing minors.
	 * We only reject dependency loops.
	 * We cannot follow the dependency chain beyond a detached or
	 * missing minor.
	 */
	if (!other_device)
		return NO_ERROR;

	/* check for loops */
	rcu_read_lock();
	while (1) {
		if (other_device == device) {
			rv = ERR_RESYNC_AFTER_CYCLE;
			break;
		}

		if (!other_device)
			break;

		if (!get_ldev_if_state(other_device, D_NEGOTIATING))
			break;
		resync_after = rcu_dereference(other_device->ldev->disk_conf)->resync_after;
		put_ldev(other_device);

		/* dependency chain ends here, no cycles. */
		if (resync_after == -1)
			break;

		/* follow the dependency chain */
		other_device = minor_to_device(resync_after);
	}
	rcu_read_unlock();

	return rv;
}

/* caller must hold resources_mutex */
void drbd_resync_after_changed(struct drbd_device *device)
{
	while (drbd_pause_after(device) || drbd_resume_next(device))
		/* do nothing */ ;
}

void drbd_rs_controller_reset(struct drbd_peer_device *peer_device)
{
	struct fifo_buffer *plan;
	struct hd_struct *part = &peer_device->device->ldev->backing_bdev->bd_contains->bd_disk->part0;

	atomic_set(&peer_device->rs_sect_in, 0);
	atomic_set(&peer_device->device->rs_sect_ev, 0);  /* FIXME: ??? */
	peer_device->rs_last_mk_req_kt = ktime_get();
	peer_device->rs_in_flight = 0;
	peer_device->rs_last_events = (int)part_stat_read(part, sectors[0])
		+ (int)part_stat_read(part, sectors[1]);

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

void start_resync_timer_fn(struct timer_list *t)
{
	struct drbd_peer_device *peer_device = from_timer(peer_device, t, start_resync_timer);
	drbd_peer_device_post_work(peer_device, RS_START);
}

bool drbd_stable_sync_source_present(struct drbd_peer_device *except_peer_device, enum which_state which)
{
	struct drbd_device *device = except_peer_device->device;
	struct drbd_peer_device *peer_device;
	u64 authoritative_nodes = 0;
	bool rv = false;

	if (!(except_peer_device->uuid_flags & UUID_FLAG_STABLE))
		authoritative_nodes = except_peer_device->uuid_node_mask;

	/* If a peer considers himself as unstable and sees me as an authoritative
	   node, then we have a stable resync source! */
	if (authoritative_nodes & NODE_MASK(device->resource->res_opts.node_id))
		return true;

	rcu_read_lock();
	for_each_peer_device_rcu(peer_device, device) {
		enum drbd_repl_state repl_state;
		struct net_conf *nc;

		if (peer_device == except_peer_device)
			continue;

		repl_state = peer_device->repl_state[which];

		if (repl_state == L_ESTABLISHED ||
				repl_state == L_WF_BITMAP_S ||
				(repl_state >= L_SYNC_SOURCE && repl_state < L_AHEAD)) {
			if (authoritative_nodes & NODE_MASK(peer_device->node_id)) {
				rv = true;
				break;
			}

			nc = rcu_dereference(peer_device->connection->transport.net_conf);
			/* Restricting the clause the two_primaries not allowed, otherwise
			   we need to ensure here that we are neighbor of all primaries,
			   and that is a lot more challenging. */

			if ((!nc->two_primaries &&
			     peer_device->connection->peer_role[which] == R_PRIMARY) ||
			    ((repl_state == L_SYNC_TARGET || repl_state == L_PAUSED_SYNC_T) &&
			     peer_device->uuid_flags & UUID_FLAG_STABLE)) {
				rv = true;
				break;
			}
		}
	}
	rcu_read_unlock();

	return rv;
}

static void do_start_resync(struct drbd_peer_device *peer_device)
{
	if (atomic_read(&peer_device->unacked_cnt) ||
	    atomic_read(&peer_device->rs_pending_cnt)) {
		drbd_warn(peer_device, "postponing start_resync ...\n");
		peer_device->start_resync_timer.expires = jiffies + HZ/10;
		add_timer(&peer_device->start_resync_timer);
		return;
	}

	drbd_start_resync(peer_device, peer_device->start_resync_side);
	clear_bit(AHEAD_TO_SYNC_SOURCE, &peer_device->flags);
}

static bool use_checksum_based_resync(struct drbd_connection *connection, struct drbd_device *device)
{
	bool csums_after_crash_only;
	rcu_read_lock();
	csums_after_crash_only = rcu_dereference(connection->transport.net_conf)->csums_after_crash_only;
	rcu_read_unlock();
	return connection->agreed_pro_version >= 89 &&		/* supported? */
		connection->csums_tfm &&			/* configured? */
		(csums_after_crash_only == false		/* use for each resync? */
		 || test_bit(CRASHED_PRIMARY, &device->flags));	/* or only after Primary crash? */
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
	enum drbd_disk_state finished_resync_pdsk = D_UNKNOWN;
	enum drbd_repl_state repl_state;
	int r;

	spin_lock_irq(&device->resource->req_lock);
	repl_state = peer_device->repl_state[NOW];
	spin_unlock_irq(&device->resource->req_lock);
	if (repl_state < L_ESTABLISHED) {
		/* Connection closed meanwhile. */
		return;
	}
	if (repl_state >= L_SYNC_SOURCE && repl_state < L_AHEAD) {
		drbd_err(peer_device, "Resync already running!\n");
		return;
	}

	if (!test_bit(B_RS_H_DONE, &peer_device->flags)) {
		if (side == L_SYNC_TARGET) {
			r = drbd_maybe_khelper(device, connection, "before-resync-target");
			if (r == DRBD_UMH_DISABLED)
				goto skip_helper;

			r = (r >> 8) & 0xff;
			if (r > 0) {
				drbd_info(device, "before-resync-target handler returned %d, "
					 "dropping connection.\n", r);
				change_cstate(connection, C_DISCONNECTING, CS_HARD);
				return;
			}
		} else /* L_SYNC_SOURCE */ {
			r = drbd_maybe_khelper(device, connection, "before-resync-source");
			if (r == DRBD_UMH_DISABLED)
				goto skip_helper;

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

skip_helper:

	if (side == L_SYNC_TARGET && drbd_current_uuid(device) == UUID_JUST_CREATED) {
		/* prepare to continue an interrupted initial resync later */
		if (get_ldev(device)) {
			const int my_node_id = device->resource->res_opts.node_id;
			u64 peer_bitmap_uuid = peer_device->bitmap_uuids[my_node_id];

			if (peer_bitmap_uuid) {
				down_write(&device->uuid_sem);
				_drbd_uuid_set_current(device, peer_bitmap_uuid);
				up_write(&device->uuid_sem);
				drbd_print_uuids(peer_device, "setting UUIDs to");
			}
			put_ldev(device);
		}
	}

	if (down_trylock(&device->resource->state_sem)) {
		/* Retry later and let the worker make progress in the
		 * meantime; two-phase commits depend on that.  */
		set_bit(B_RS_H_DONE, &peer_device->flags);
		peer_device->start_resync_side = side;
		peer_device->start_resync_timer.expires = jiffies + HZ/5;
		add_timer(&peer_device->start_resync_timer);
		return;
	}

	lock_all_resources();
	clear_bit(B_RS_H_DONE, &peer_device->flags);
	if (connection->cstate[NOW] < C_CONNECTED ||
	    !get_ldev_if_state(device, D_NEGOTIATING)) {
		unlock_all_resources();
		goto out;
	}

	begin_state_change_locked(device->resource, CS_VERBOSE);
	__change_resync_susp_dependency(peer_device, !__drbd_may_sync_now(peer_device));
	__change_repl_state(peer_device, side);
	if (side == L_SYNC_TARGET)
		init_resync_stable_bits(peer_device);
	finished_resync_pdsk = peer_device->resync_finished_pdsk;
	peer_device->resync_finished_pdsk = D_UNKNOWN;
	r = end_state_change_locked(device->resource);
	repl_state = peer_device->repl_state[NOW];

	if (repl_state < L_ESTABLISHED)
		r = SS_UNKNOWN_ERROR;

	if (r == SS_SUCCESS) {
		if (side == L_SYNC_TARGET)
			drbd_set_exposed_data_uuid(device, peer_device->current_uuid);

		drbd_pause_after(device);
		/* Forget potentially stale cached per resync extent bit-counts.
		 * Open coded drbd_rs_cancel_all(device), we already have IRQs
		 * disabled, and know the disk state is ok. */
		spin_lock(&device->al_lock);
		lc_reset(peer_device->resync_lru);
		peer_device->resync_locked = 0;
		peer_device->resync_wenr = LC_FREE;
		spin_unlock(&device->al_lock);
	}

	unlock_all_resources();

	if (r == SS_SUCCESS) {
		drbd_info(peer_device, "Began resync as %s (will sync %lu KB [%lu bits set]).\n",
		     drbd_repl_str(repl_state),
		     (unsigned long) peer_device->rs_total << (BM_BLOCK_SHIFT-10),
		     (unsigned long) peer_device->rs_total);
		if (side == L_SYNC_TARGET) {
			peer_device->resync_next_bit = 0;
			peer_device->use_csums = use_checksum_based_resync(connection, device);
		} else {
			peer_device->use_csums = false;
		}

		if ((side == L_SYNC_TARGET || side == L_PAUSED_SYNC_T) &&
		    !(peer_device->uuid_flags & UUID_FLAG_STABLE) &&
		    !drbd_stable_sync_source_present(peer_device, NOW))
			set_bit(UNSTABLE_RESYNC, &peer_device->flags);

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
				nc = rcu_dereference(connection->transport.net_conf);
				timeo = nc->ping_int * HZ + nc->ping_timeo * HZ / 9;
				rcu_read_unlock();
				schedule_timeout_interruptible(timeo);
			}
			drbd_resync_finished(peer_device, D_MASK);
		}

		/* ns.conn may already be != peer_device->repl_state[NOW],
		 * we may have been paused in between, or become paused until
		 * the timer triggers.
		 * No matter, that is handled in resync_timer_fn() */
		if (repl_state == L_SYNC_TARGET) {
			drbd_uuid_resync_starting(peer_device);
			mod_timer(&peer_device->resync_timer, jiffies);
		}

		drbd_md_sync_if_dirty(device);
	}
	put_ldev(device);
    out:
	up(&device->resource->state_sem);
	if (finished_resync_pdsk != D_UNKNOWN)
		drbd_resync_finished(peer_device, finished_resync_pdsk);
}

static void update_on_disk_bitmap(struct drbd_peer_device *peer_device, bool resync_done)
{
	struct drbd_device *device = peer_device->device;
	peer_device->rs_last_writeout = jiffies;

	if (!get_ldev(device))
		return;

	drbd_bm_write_lazy(device, 0);

	if (resync_done) {
		if (is_verify_state(peer_device, NOW)) {
			ov_out_of_sync_print(peer_device);
			ov_skipped_print(peer_device);
		} else
			resync_done = is_sync_state(peer_device, NOW);
	}
	if (resync_done)
		drbd_resync_finished(peer_device, D_MASK);

	/* update timestamp, in case it took a while to write out stuff */
	peer_device->rs_last_writeout = jiffies;
	put_ldev(device);
}

static void drbd_ldev_destroy(struct drbd_device *device)
{
        struct drbd_peer_device *peer_device;

        rcu_read_lock();
        for_each_peer_device_rcu(peer_device, device) {
                lc_destroy(peer_device->resync_lru);
                peer_device->resync_lru = NULL;
        }
        rcu_read_unlock();
        lc_destroy(device->act_log);
        device->act_log = NULL;
	__acquire(local);
	drbd_backing_dev_free(device, device->ldev);
	device->ldev = NULL;
	__release(local);

        clear_bit(GOING_DISKLESS, &device->flags);
	wake_up(&device->misc_wait);
}

static void go_diskless(struct drbd_device *device)
{
	D_ASSERT(device, device->disk_state[NOW] == D_FAILED ||
			 device->disk_state[NOW] == D_DETACHING);
	/* we cannot assert local_cnt == 0 here, as get_ldev_if_state will
	 * inc/dec it frequently. Once we are D_DISKLESS, no one will touch
	 * the protected members anymore, though, so once put_ldev reaches zero
	 * again, it will be safe to free them. */

	/* Try to write changed bitmap pages, read errors may have just
	 * set some bits outside the area covered by the activity log.
	 *
	 * If we have an IO error during the bitmap writeout,
	 * we will want a full sync next time, just in case.
	 * (Do we want a specific meta data flag for this?)
	 *
	 * If that does not make it to stable storage either,
	 * we cannot do anything about that anymore.
	 *
	 * We still need to check if both bitmap and ldev are present, we may
	 * end up here after a failed attach, before ldev was even assigned.
	 */
	if (device->bitmap && device->ldev) {
		if (drbd_bitmap_io_from_worker(device, drbd_bm_write,
					       "detach",
					       BM_LOCK_SET | BM_LOCK_CLEAR | BM_LOCK_BULK,
					       NULL)) {
			if (test_bit(CRASHED_PRIMARY, &device->flags)) {
				struct drbd_peer_device *peer_device;

				rcu_read_lock();
				for_each_peer_device_rcu(peer_device, device)
					drbd_md_set_peer_flag(peer_device, MDF_PEER_FULL_SYNC);
				rcu_read_unlock();
				drbd_md_sync_if_dirty(device);
			}
		}
	}

	change_disk_state(device, D_DISKLESS, CS_HARD, NULL);
}

static int do_md_sync(struct drbd_device *device)
{
	drbd_warn(device, "md_sync_timer expired! Worker calls drbd_md_sync().\n");
	drbd_md_sync(device);
	return 0;
}

void repost_up_to_date_fn(struct timer_list *t)
{
	struct drbd_resource *resource = from_timer(resource, t, repost_up_to_date_timer);
	drbd_post_work(resource, TRY_BECOME_UP_TO_DATE);
}

static int try_become_up_to_date(struct drbd_resource *resource)
{
	enum drbd_state_rv rv;

	/* Doing a two_phase_commit from worker context is only possible
	 * if twopc_work is not queued. Let it get executed first.
	 *
	 * Avoid deadlock on state_sem, in case someone holds it while
	 * waiting for the completion of some after-state-change work.
	 */
	if (list_empty(&resource->twopc_work.list)) {
		if (down_trylock(&resource->state_sem))
			goto repost;
		rv = change_from_consistent(resource, CS_ALREADY_SERIALIZED |
			CS_VERBOSE | CS_SERIALIZE | CS_DONT_RETRY);
		up(&resource->state_sem);
		if (rv == SS_TIMEOUT || rv == SS_CONCURRENT_ST_CHG)
			goto repost;
		drbd_notify_peers_lost_primary(resource);
	} else {
	repost:
		mod_timer(&resource->repost_up_to_date_timer, jiffies + HZ/10);
	}

	return 0;
}

/* only called from drbd_worker thread, no locking */
void __update_timing_details(
		struct drbd_thread_timing_details *tdp,
		unsigned int *cb_nr,
		void *cb,
		const char *fn, const unsigned int line)
{
	unsigned int i = *cb_nr % DRBD_THREAD_DETAILS_HIST;
	struct drbd_thread_timing_details *td = tdp + i;

	td->start_jif = jiffies;
	td->cb_addr = cb;
	td->caller_fn = fn;
	td->line = line;
	td->cb_nr = *cb_nr;

	i = (i+1) % DRBD_THREAD_DETAILS_HIST;
	td = tdp + i;
	memset(td, 0, sizeof(*td));

	++(*cb_nr);
}

static bool all_peers_responded(struct drbd_resource *resource)
{
	struct drbd_connection *connection;
	bool all_responded = true;

	rcu_read_lock();
	for_each_connection_rcu(connection, resource) {
		if (!test_bit(CHECKING_PEER, &connection->flags))
			continue;
		if (connection->cstate[NOW] < C_CONNECTED) {
			clear_bit(CHECKING_PEER, &connection->flags);
			continue;
		}
		if (!test_bit(GOT_PING_ACK, &connection->flags)) {
			all_responded = false;
			break;
		}
	}
	rcu_read_unlock();

	return all_responded;
}

void drbd_check_peers(struct drbd_resource *resource)
{
	struct drbd_connection *connection;
	bool check_ongoing;
	u64 im;

	check_ongoing = test_and_set_bit(CHECKING_PEERS, &resource->flags);
	if (check_ongoing) {
		wait_event(resource->state_wait,
			   !test_bit(CHECKING_PEERS, &resource->flags));
		return;
	}

	for_each_connection_ref(connection, im, resource) {
		if (connection->cstate[NOW] < C_CONNECTED)
			continue;
		clear_bit(GOT_PING_ACK, &connection->flags);
		set_bit(CHECKING_PEER, &connection->flags);
		request_ping(connection);
	}

	wait_event(resource->state_wait, all_peers_responded(resource));

	clear_bit(CHECKING_PEERS, &resource->flags);
	wake_up(&resource->state_wait);
}

void drbd_check_peers_new_current_uuid(struct drbd_device *device)
{
	struct drbd_resource *resource = device->resource;

	drbd_check_peers(resource);

	if (device->have_quorum[NOW] && drbd_data_accessible(device, NOW))
		drbd_uuid_new_current(device, false);
}

static void make_new_current_uuid(struct drbd_device *device)
{
	drbd_check_peers_new_current_uuid(device);

	get_work_bits(1UL << NEW_CUR_UUID | 1UL << WRITING_NEW_CUR_UUID, &device->flags);
	wake_up(&device->misc_wait);
}

static void do_device_work(struct drbd_device *device, const unsigned long todo)
{
	if (test_bit(MD_SYNC, &todo))
		do_md_sync(device);
	if (test_bit(GO_DISKLESS, &todo))
		go_diskless(device);
	if (test_bit(DESTROY_DISK, &todo))
		drbd_ldev_destroy(device);
	if (test_bit(MAKE_NEW_CUR_UUID, &todo))
		make_new_current_uuid(device);
}

static void do_peer_device_work(struct drbd_peer_device *peer_device, const unsigned long todo)
{
	if (test_bit(RS_PROGRESS, &todo))
		drbd_broadcast_peer_device_state(peer_device);
	if (test_bit(RS_DONE, &todo) ||
	    test_bit(RS_LAZY_BM_WRITE, &todo))
		update_on_disk_bitmap(peer_device, test_bit(RS_DONE, &todo));
	if (test_bit(RS_START, &todo))
		do_start_resync(peer_device);
}

#define DRBD_RESOURCE_WORK_MASK	\
	(1UL << TRY_BECOME_UP_TO_DATE)

#define DRBD_DEVICE_WORK_MASK	\
	((1UL << GO_DISKLESS)	\
	|(1UL << DESTROY_DISK)	\
	|(1UL << MD_SYNC)	\
	|(1UL << MAKE_NEW_CUR_UUID)\
	)

#define DRBD_PEER_DEVICE_WORK_MASK	\
	((1UL << RS_START)		\
	|(1UL << RS_LAZY_BM_WRITE)	\
	|(1UL << RS_PROGRESS)		\
	|(1UL << RS_DONE)		\
	)

static unsigned long get_work_bits(const unsigned long mask, unsigned long *flags)
{
	unsigned long old, new;
	do {
		old = *flags;
		new = old & ~mask;
	} while (cmpxchg(flags, old, new) != old);
	return old & mask;
}

static void __do_unqueued_peer_device_work(struct drbd_connection *connection)
{
	struct drbd_peer_device *peer_device;
	int vnr;

	rcu_read_lock();
	idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
		struct drbd_device *device = peer_device->device;
		unsigned long todo = get_work_bits(DRBD_PEER_DEVICE_WORK_MASK, &peer_device->flags);
		if (!todo)
			continue;

		kref_get(&device->kref);
		rcu_read_unlock();
		do_peer_device_work(peer_device, todo);
		kref_put(&device->kref, drbd_destroy_device);
		rcu_read_lock();
	}
	rcu_read_unlock();
}

static void do_unqueued_peer_device_work(struct drbd_resource *resource)
{
	struct drbd_connection *connection;
	u64 im;

	for_each_connection_ref(connection, im, resource)
		__do_unqueued_peer_device_work(connection);
}

static void do_unqueued_device_work(struct drbd_resource *resource)
{
	struct drbd_device *device;
	int vnr;

	rcu_read_lock();
	idr_for_each_entry(&resource->devices, device, vnr) {
		unsigned long todo = get_work_bits(DRBD_DEVICE_WORK_MASK, &device->flags);
		if (!todo)
			continue;

		kref_get(&device->kref);
		rcu_read_unlock();
		do_device_work(device, todo);
		kref_put(&device->kref, drbd_destroy_device);
		rcu_read_lock();
	}
	rcu_read_unlock();
}

static void do_unqueued_resource_work(struct drbd_resource *resource)
{
	unsigned long todo = get_work_bits(DRBD_RESOURCE_WORK_MASK, &resource->flags);

	if (test_bit(TRY_BECOME_UP_TO_DATE, &todo))
		try_become_up_to_date(resource);
}

static bool dequeue_work_batch(struct drbd_work_queue *queue, struct list_head *work_list)
{
	spin_lock_irq(&queue->q_lock);
	list_splice_tail_init(&queue->q, work_list);
	spin_unlock_irq(&queue->q_lock);
	return !list_empty(work_list);
}

static struct drbd_request *__next_request_for_connection(
		struct drbd_connection *connection, struct drbd_request *r)
{
	r = list_prepare_entry(r, &connection->resource->transfer_log, tl_requests);
	list_for_each_entry_continue(r, &connection->resource->transfer_log, tl_requests) {
		int vnr = r->device->vnr;
		struct drbd_peer_device *peer_device = conn_peer_device(connection, vnr);
		unsigned s = drbd_req_state_by_peer_device(r, peer_device);
		if (!(s & RQ_NET_QUEUED))
			continue;
		return r;
	}
	return NULL;
}

/* holds req_lock on entry, may give up and reacquire temporarily */
static struct drbd_request *tl_mark_for_resend_by_connection(struct drbd_connection *connection)
{
	struct bio_and_error m;
	struct drbd_request *req;
	struct drbd_request *req_oldest = NULL;
	struct drbd_request *tmp = NULL;
	struct drbd_device *device;
	struct drbd_peer_device *peer_device;
	unsigned s;

	/* In the unlikely case that we need to give up the spinlock
	 * temporarily below, we need to restart the loop, as the request
	 * pointer, or any next pointers, may become invalid meanwhile.
	 *
	 * We can restart from a known safe position, though:
	 * the last request we successfully marked for resend,
	 * without it disappearing.
	 */
restart:
	req = list_prepare_entry(tmp, &connection->resource->transfer_log, tl_requests);
	list_for_each_entry_continue(req, &connection->resource->transfer_log, tl_requests) {
		/* potentially needed in complete_master_bio below */
		device = req->device;
		peer_device = conn_peer_device(connection, device->vnr);
		s = drbd_req_state_by_peer_device(req, peer_device);

		if (!(s & RQ_NET_MASK))
			continue;

		/* if it is marked QUEUED, it can not be an old one,
		 * so we can stop marking for RESEND here. */
		if (s & RQ_NET_QUEUED)
			break;

		/* Skip old requests which are uninteresting for this connection.
		 * Could happen, if this connection was restarted,
		 * while some other connection was lagging seriously. */
		if (s & RQ_NET_DONE)
			continue;

		/* FIXME what about QUEUE_FOR_SEND_OOS?
		 * Is it even possible to encounter those here?
		 * It should not.
		 */
		if (drbd_req_is_write(req))
			expect(peer_device, s & RQ_EXP_BARR_ACK);

		__req_mod(req, RESEND, peer_device, &m);

		/* If this is now RQ_NET_PENDING (it should), it won't
		 * disappear, even if we give up the spinlock below. */
		if (drbd_req_state_by_peer_device(req, peer_device) & RQ_NET_PENDING)
			tmp = req;

		/* We crunch through a potentially very long list, so be nice
		 * and eventually temporarily give up the spinlock/re-enable
		 * interrupts.
		 *
		 * Also, in the very unlikely case that trying to mark it for
		 * RESEND actually caused this request to be finished off, we
		 * complete the master bio, outside of the lock. */
		if (m.bio || need_resched()) {
			spin_unlock_irq(&connection->resource->req_lock);
			if (m.bio)
				complete_master_bio(device, &m);
			cond_resched();
			spin_lock_irq(&connection->resource->req_lock);
			goto restart;
		}
		if (!req_oldest)
			req_oldest = req;
	}
	return req_oldest;
}

static struct drbd_request *tl_next_request_for_connection(struct drbd_connection *connection)
{
	if (connection->todo.req_next == TL_NEXT_REQUEST_RESEND)
		connection->todo.req_next = tl_mark_for_resend_by_connection(connection);

	else if (connection->todo.req_next == NULL)
		connection->todo.req_next = __next_request_for_connection(connection, NULL);

	connection->todo.req = connection->todo.req_next;

	/* advancement of todo.req_next happens in advance_conn_req_next(),
	 * called from mod_rq_state() */

	return connection->todo.req;
}

static void maybe_send_state_afer_ahead(struct drbd_connection *connection)
{
	struct drbd_peer_device *peer_device;
	int vnr;

	rcu_read_lock();
	idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
		if (test_and_clear_bit(SEND_STATE_AFTER_AHEAD, &peer_device->flags)) {
			peer_device->todo.was_ahead = false;
			rcu_read_unlock();
			drbd_send_current_state(peer_device);
			rcu_read_lock();
		}
	}
	rcu_read_unlock();
}

/* This finds the next not yet processed request from
 * connection->resource->transfer_log.
 * It also moves all currently queued connection->sender_work
 * to connection->todo.work_list.
 */
static bool check_sender_todo(struct drbd_connection *connection)
{
	tl_next_request_for_connection(connection);

	/* we did lock_irq above already. */
	/* FIXME can we get rid of this additional lock? */
	spin_lock(&connection->sender_work.q_lock);
	list_splice_tail_init(&connection->sender_work.q, &connection->todo.work_list);
	spin_unlock(&connection->sender_work.q_lock);

	return connection->todo.req
		|| need_unplug(connection)
		|| !list_empty(&connection->todo.work_list);
}

static void wait_for_sender_todo(struct drbd_connection *connection)
{
	DEFINE_WAIT(wait);
	struct net_conf *nc;
	int uncork, cork;
	bool got_something = 0;

	spin_lock_irq(&connection->resource->req_lock);
	got_something = check_sender_todo(connection);
	spin_unlock_irq(&connection->resource->req_lock);
	if (got_something)
		return;

	/* Still nothing to do?
	 * Maybe we still need to close the current epoch,
	 * even if no new requests are queued yet.
	 *
	 * Also, poke TCP, just in case.
	 * Then wait for new work (or signal). */
	rcu_read_lock();
	nc = rcu_dereference(connection->transport.net_conf);
	uncork = nc ? nc->tcp_cork : 0;
	rcu_read_unlock();
	if (uncork)
		drbd_uncork(connection, DATA_STREAM);

	for (;;) {
		int send_barrier;
		prepare_to_wait(&connection->sender_work.q_wait, &wait,
				TASK_INTERRUPTIBLE);
		spin_lock_irq(&connection->resource->req_lock);
		if (check_sender_todo(connection) || signal_pending(current)) {
			spin_unlock_irq(&connection->resource->req_lock);
			break;
		}

		/* We found nothing new to do, no to-be-communicated request,
		 * no other work item.  We may still need to close the last
		 * epoch.  Next incoming request epoch will be connection ->
		 * current transfer log epoch number.  If that is different
		 * from the epoch of the last request we communicated, it is
		 * safe to send the epoch separating barrier now.
		 */
		send_barrier = should_send_barrier(connection,
					atomic_read(&connection->resource->current_tle_nr));
		spin_unlock_irq(&connection->resource->req_lock);

		if (send_barrier) {
			finish_wait(&connection->sender_work.q_wait, &wait);
			maybe_send_barrier(connection,
					connection->send.current_epoch_nr + 1);
			continue;
		}

		if (test_and_clear_bit(SEND_STATE_AFTER_AHEAD_C, &connection->flags)) {
			finish_wait(&connection->sender_work.q_wait, &wait);
			maybe_send_state_afer_ahead(connection);
			continue;
		}

		/* drbd_send() may have called flush_signals() */
		if (get_t_state(&connection->sender) != RUNNING)
			break;

		schedule();
		/* may be woken up for other things but new work, too,
		 * e.g. if the current epoch got closed.
		 * In which case we send the barrier above. */
	}
	finish_wait(&connection->sender_work.q_wait, &wait);

	/* someone may have changed the config while we have been waiting above. */
	rcu_read_lock();
	nc = rcu_dereference(connection->transport.net_conf);
	cork = nc ? nc->tcp_cork : 0;
	rcu_read_unlock();

	if (cork)
		drbd_cork(connection, DATA_STREAM);
	else if (!uncork)
		drbd_uncork(connection, DATA_STREAM);
}

static void re_init_if_first_write(struct drbd_connection *connection, unsigned int epoch)
{
	if (!connection->send.seen_any_write_yet) {
		connection->send.seen_any_write_yet = true;
		connection->send.current_epoch_nr = epoch;
		connection->send.current_epoch_writes = 0;
		connection->send.last_sent_barrier_jif = jiffies;
		connection->send.current_dagtag_sector =
			connection->resource->dagtag_sector - ((BIO_MAX_PAGES << PAGE_SHIFT) >> 9) - 1;
	}
}

static bool should_send_barrier(struct drbd_connection *connection, unsigned int epoch)
{
	if (!connection->send.seen_any_write_yet)
		return false;
	return connection->send.current_epoch_nr != epoch;
}
static void maybe_send_barrier(struct drbd_connection *connection, unsigned int epoch)
{
	/* re-init if first write on this connection */
	if (should_send_barrier(connection, epoch)) {
		if (connection->send.current_epoch_writes)
			drbd_send_barrier(connection);
		connection->send.current_epoch_nr = epoch;
	}
}

static bool is_write_in_flight(struct drbd_peer_device *peer_device, struct drbd_interval *in)
{
	struct drbd_device *device = peer_device->device;
	struct drbd_request *req;
	struct drbd_interval *i;
	sector_t sector = in->sector;
	int size = in->size;
	int idx = peer_device->node_id;
	int s;
	bool in_flight = false;

	if (idx < 0 || idx >= DRBD_NODE_ID_MAX) {
		drbd_warn(peer_device, "is_write_in_flight: BAD idx: %d\n", idx);
		return false;
	}

	spin_lock_irq(&device->resource->req_lock);
	drbd_for_each_overlap(i, &device->write_requests, sector, size) {
		if (i == in)
			continue;
		if (!i->local)
			continue;
		/* don't care for i->completed, in DRBD_PROT_A we
		 * are more interested in RQ_NET_DONE instead */
		req = container_of(i, struct drbd_request, i);
		s = req->net_rq_state[idx];
		if ((s & RQ_NET_SENT) == 0) /* not even sent: ignore */
			continue;
		if ((s & RQ_NET_DONE) == RQ_NET_DONE) /* already done: ignore */
			continue;
		in_flight = true;
		break;
	}
	spin_unlock_irq(&device->resource->req_lock);
	return in_flight;
}

static int process_one_request(struct drbd_connection *connection)
{
	struct bio_and_error m;
	struct drbd_request *req = connection->todo.req;
	struct drbd_device *device = req->device;
	struct drbd_peer_device *peer_device =
			conn_peer_device(connection, device->vnr);
	unsigned s = drbd_req_state_by_peer_device(req, peer_device);
	bool do_send_unplug = req->local_rq_state & RQ_UNPLUG;
	int err = 0;
	enum drbd_req_event what;

	/* pre_send_jif[] is used in net_timeout_reached() */
	req->pre_send_jif[peer_device->node_id] = jiffies;
	ktime_get_accounting(req->pre_send_kt[peer_device->node_id]);
	if (drbd_req_is_write(req)) {
		/* If a WRITE does not expect a barrier ack,
		 * we are supposed to only send an "out of sync" info packet */
		if (s & RQ_EXP_BARR_ACK) {
			u64 current_dagtag_sector =
				req->dagtag_sector - (req->i.size >> 9);

			re_init_if_first_write(connection, req->epoch);
			maybe_send_barrier(connection, req->epoch);
			if (current_dagtag_sector != connection->send.current_dagtag_sector)
				drbd_send_dagtag(connection, current_dagtag_sector);

			connection->send.current_epoch_writes++;
			connection->send.current_dagtag_sector = req->dagtag_sector;

			if (peer_device->todo.was_ahead) {
				clear_bit(SEND_STATE_AFTER_AHEAD, &peer_device->flags);
				peer_device->todo.was_ahead = false;
				drbd_send_current_state(peer_device);
			}

			err = drbd_send_dblock(peer_device, req);
			what = err ? SEND_FAILED : HANDED_OVER_TO_NETWORK;
		} else {
			/* this time, no connection->send.current_epoch_writes++;
			 * If it was sent, it was the closing barrier for the last
			 * replicated epoch, before we went into AHEAD mode.
			 * No more barriers will be sent, until we leave AHEAD mode again. */
			maybe_send_barrier(connection, req->epoch);

			/* make sure the state change to L_AHEAD/L_BEHIND
			 * arrives before the first set-out-of-sync information */
			if (!peer_device->todo.was_ahead) {
				peer_device->todo.was_ahead = true;
				drbd_send_current_state(peer_device);
			}

			/* Scenario:
			 * L_ESTABLISHED -> L_AHEAD -> L_SYNC_SOURCE -> L_AHEAD
			 *  a) during first L_AHEAD, we send, and set, out-of-sync,
			 *  b) during L_SYNC_SOURCE, we send a normal write (above),
			 *  c) during second L_AHEAD, we again send + set out-of-sync
			 * all for the same block.
			 * The "normal write during resync" may set the block
			 * in-sync on completion/destruction.
			 * We must make sure that won't race
			 * race with the second set out-of-sync.
			 *
			 * In drbd_send_and_submit(), we introduce a dependency
			 * via req->destroy_next, where the older (WRITE) requests
			 * hold a kref on the younger ones, so we can be sure the
			 * destructor is processed in oldest-to-youngest order.
			 *
			 * Even if the P_RS_WRITE_ACK for the write
			 * during-resync (b) is received *after* the completion
			 * of the second send+set out-of-sync (c), the ordering
			 * of the destructors will only temporarily set
			 * in-sync, then set out-of-sync again "soon enough",
			 * at least on this node.
			 *
			 * As an optimization, if during L_AHEAD the same
			 * block(s) are overwritten several times, we may skip
			 * the send-out-of-sync, if we know we told the peer
			 * before. But we must NOT skip, if there is still a
			 * normal write in-flight to the peer (as per the
			 * scenario above).  We check using our interval tree.
			 */
			if (drbd_set_out_of_sync(peer_device, req->i.sector, req->i.size) ||
			    is_write_in_flight(peer_device, &req->i))
				err = drbd_send_out_of_sync(peer_device, req->i.sector, req->i.size);
			what = OOS_HANDED_TO_NETWORK; /* Well, most of the time, anyways. */
		}
	} else {
		maybe_send_barrier(connection, req->epoch);
		err = drbd_send_drequest(peer_device, P_DATA_REQUEST,
				req->i.sector, req->i.size, (unsigned long)req);
		what = err ? SEND_FAILED : HANDED_OVER_TO_NETWORK;
	}

	spin_lock_irq(&connection->resource->req_lock);
	__req_mod(req, what, peer_device, &m);

	/* As we hold the request lock anyways here,
	 * this is a convenient place to check for new things to do. */
	check_sender_todo(connection);

	spin_unlock_irq(&connection->resource->req_lock);

	if (m.bio)
		complete_master_bio(device, &m);

	do_send_unplug = do_send_unplug && what == HANDED_OVER_TO_NETWORK;
	maybe_send_unplug_remote(connection, do_send_unplug);

	return err;
}

static int process_sender_todo(struct drbd_connection *connection)
{
	struct drbd_work *w = NULL;

	/* Process all currently pending work items,
	 * or requests from the transfer log.
	 *
	 * Right now, work items do not require any strict ordering wrt. the
	 * request stream, so lets just do simple interleaved processing.
	 *
	 * Stop processing as soon as an error is encountered.
	 */
	if (!connection->todo.req) {
		update_sender_timing_details(connection, maybe_send_unplug_remote);
		maybe_send_unplug_remote(connection, false);
	}
	else if (list_empty(&connection->todo.work_list)) {
		update_sender_timing_details(connection, process_one_request);
		return process_one_request(connection);
	}

	while (!list_empty(&connection->todo.work_list)) {
		int err;

		w = list_first_entry(&connection->todo.work_list, struct drbd_work, list);
		list_del_init(&w->list);
		update_sender_timing_details(connection, w->cb);
		err = w->cb(w, connection->cstate[NOW] < C_CONNECTED);
		if (err)
			return err;

		/* If we would need strict ordering for work items, we could
		 * add a dagtag member to struct drbd_work, and serialize based on that.
		 * && !dagtag_newer(connection->todo.req->dagtag_sector, w->dagtag_sector))
		 * to the following condition. */
		if (connection->todo.req) {
			update_sender_timing_details(connection, process_one_request);
			err = process_one_request(connection);
		}
		if (err)
			return err;
	}

	return 0;
}

int drbd_sender(struct drbd_thread *thi)
{
	struct drbd_connection *connection = thi->connection;
	struct drbd_work *w;
	struct drbd_peer_device *peer_device;
	int vnr;
	int err;

	/* Should we drop this? Or reset even more stuff? */
	rcu_read_lock();
	idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
		peer_device->send_cnt = 0;
		peer_device->recv_cnt = 0;
	}
	rcu_read_unlock();

	while (get_t_state(thi) == RUNNING) {
		drbd_thread_current_set_cpu(thi);

		if (list_empty(&connection->todo.work_list) &&
		    connection->todo.req == NULL) {
			update_sender_timing_details(connection, wait_for_sender_todo);
			wait_for_sender_todo(connection);
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

		err = process_sender_todo(connection);
		if (err)
			change_cstate(connection, C_NETWORK_FAILURE, CS_HARD);
	}

	/* cleanup all currently unprocessed requests */
	if (!connection->todo.req) {
		spin_lock_irq(&connection->resource->req_lock);
		tl_next_request_for_connection(connection);
		spin_unlock_irq(&connection->resource->req_lock);
	}
	while (connection->todo.req) {
		struct bio_and_error m;
		struct drbd_request *req = connection->todo.req;
		struct drbd_device *device = req->device;
		peer_device = conn_peer_device(connection, device->vnr);

		spin_lock_irq(&connection->resource->req_lock);
		__req_mod(req, SEND_CANCELED, peer_device, &m);
		tl_next_request_for_connection(connection);
		spin_unlock_irq(&connection->resource->req_lock);
		if (m.bio)
			complete_master_bio(device, &m);
	}

	/* cancel all still pending works */
	do {
		while (!list_empty(&connection->todo.work_list)) {
			w = list_first_entry(&connection->todo.work_list, struct drbd_work, list);
			list_del_init(&w->list);
			w->cb(w, 1);
		}
		dequeue_work_batch(&connection->sender_work, &connection->todo.work_list);
	} while (!list_empty(&connection->todo.work_list));

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
			bool w, r, d, p;

			update_worker_timing_details(resource, dequeue_work_batch);
			wait_event_interruptible(resource->work.q_wait,
				(w = dequeue_work_batch(&resource->work, &work_list),
				 r = test_and_clear_bit(RESOURCE_WORK_PENDING, &resource->flags),
				 d = test_and_clear_bit(DEVICE_WORK_PENDING, &resource->flags),
				 p = test_and_clear_bit(PEER_DEVICE_WORK_PENDING, &resource->flags),
				 w || r || d || p));

			if (p) {
				update_worker_timing_details(resource, do_unqueued_peer_device_work);
				do_unqueued_peer_device_work(resource);
			}

			if (d) {
				update_worker_timing_details(resource, do_unqueued_device_work);
				do_unqueued_device_work(resource);
			}
			if (r) {
				update_worker_timing_details(resource, do_unqueued_resource_work);
				do_unqueued_resource_work(resource);
			}
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
			update_worker_timing_details(resource, w->cb);
			w->cb(w, 0);
		}
	}

	do {
		if (test_and_clear_bit(RESOURCE_WORK_PENDING, &resource->flags)) {
			update_worker_timing_details(resource, do_unqueued_resource_work);
			do_unqueued_resource_work(resource);
		}
		if (test_and_clear_bit(DEVICE_WORK_PENDING, &resource->flags)) {
			update_worker_timing_details(resource, do_unqueued_device_work);
			do_unqueued_device_work(resource);
		}
		if (test_and_clear_bit(PEER_DEVICE_WORK_PENDING, &resource->flags)) {
			update_worker_timing_details(resource, do_unqueued_peer_device_work);
			do_unqueued_peer_device_work(resource);
		}
		while (!list_empty(&work_list)) {
			w = list_first_entry(&work_list, struct drbd_work, list);
			list_del_init(&w->list);
			update_worker_timing_details(resource, w->cb);
			w->cb(w, 1);
		}
		dequeue_work_batch(&resource->work, &work_list);
	} while (!list_empty(&work_list) ||
		 test_bit(DEVICE_WORK_PENDING, &resource->flags) ||
		 test_bit(PEER_DEVICE_WORK_PENDING, &resource->flags));

	return 0;
}
