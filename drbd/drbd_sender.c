// SPDX-License-Identifier: GPL-2.0-only
/*
   drbd_sender.c

   This file is part of DRBD by Philipp Reisner and Lars Ellenberg.

   Copyright (C) 2001-2008, LINBIT Information Technologies GmbH.
   Copyright (C) 1999-2008, Philipp Reisner <philipp.reisner@linbit.com>.
   Copyright (C) 2002-2008, Lars Ellenberg <lars.ellenberg@linbit.com>.


 */

#include <linux/drbd.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/wait.h>
#include <linux/mm.h>
#include <linux/memcontrol.h> /* needed on kernels <4.3 */
#include <linux/mm_inline.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/overflow.h>
#include <linux/part_stat.h>

#include "drbd_int.h"
#include "drbd_protocol.h"
#include "drbd_req.h"
#include "drbd_meta_data.h"

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
	struct drbd_peer_device *peer_device = peer_req->peer_device;
	struct drbd_device *device = peer_device->device;
	struct drbd_connection *connection = peer_device->connection;
	bool io_error;

	device->read_cnt += peer_req->i.size >> 9;
	io_error = test_bit(__EE_WAS_ERROR, &peer_req->flags);

	drbd_queue_work(&connection->sender_work, &peer_req->w);
	peer_req = NULL; /* peer_req may be freed. */

	/*
	 * Decrement counter after queuing work to avoid a moment where
	 * backing_ee_cnt is zero and the sender work list is empty.
	 */
	if (atomic_dec_and_test(&connection->backing_ee_cnt))
		wake_up(&connection->ee_wait);

	if (io_error)
		drbd_handle_io_error(device, DRBD_READ_ERROR);

	put_ldev(device);
}

static int is_failed_barrier(int ee_flags)
{
	return (ee_flags & (EE_IS_BARRIER|EE_WAS_ERROR|EE_RESUBMITTED|EE_TRIM|EE_ZEROOUT))
		== (EE_IS_BARRIER|EE_WAS_ERROR);
}

static bool drbd_peer_request_is_merged(struct drbd_peer_request *peer_req,
		sector_t main_sector, sector_t main_sector_end)
{
	/*
	 * We do not send overlapping resync requests. So any request which is
	 * in the corresponding range and for which we have received a reply
	 * must be a merged request. EE_TRIM implies that we have received a
	 * reply.
	 */
	return peer_req->i.sector >= main_sector &&
		peer_req->i.sector + (peer_req->i.size >> SECTOR_SHIFT) <= main_sector_end &&
			peer_req->i.type == INTERVAL_RESYNC_WRITE &&
			(peer_req->flags & EE_TRIM);
}

int drbd_unmerge_discard(struct drbd_peer_request *peer_req_main, struct list_head *list)
{
	struct drbd_peer_device *peer_device = peer_req_main->peer_device;
	struct drbd_peer_request *peer_req = peer_req_main;
	sector_t main_sector = peer_req_main->i.sector;
	sector_t main_sector_end = main_sector + (peer_req_main->i.size >> SECTOR_SHIFT);
	int merged_count = 0;

	list_for_each_entry_continue(peer_req, &peer_device->resync_requests, recv_order) {
		if (!drbd_peer_request_is_merged(peer_req, main_sector, main_sector_end))
			break;

		merged_count++;
		list_add_tail(&peer_req->w.list, list);
	}

	return merged_count;
}

/* writes on behalf of the partner, or resync writes,
 * "submitted" by the receiver, final stage.  */
void drbd_endio_write_sec_final(struct drbd_peer_request *peer_req) __releases(local)
{
	unsigned long flags = 0;
	struct drbd_peer_device *peer_device = peer_req->peer_device;
	struct drbd_device *device = peer_device->device;
	struct drbd_connection *connection = peer_device->connection;
	enum drbd_interval_type type;
	bool do_wake;

	/* if this is a failed barrier request, disable use of barriers,
	 * and schedule for resubmission */
	if (is_failed_barrier(peer_req->flags)) {
		drbd_bump_write_ordering(device->resource, device->ldev, WO_BDEV_FLUSH);
		spin_lock_irqsave(&connection->peer_reqs_lock, flags);
		peer_req->flags = (peer_req->flags & ~EE_WAS_ERROR) | EE_RESUBMITTED;
		peer_req->w.cb = w_e_reissue;
		/* put_ldev actually happens below, once we come here again. */
		__release(local);
		spin_unlock_irqrestore(&connection->peer_reqs_lock, flags);
		drbd_queue_work(&connection->sender_work, &peer_req->w);
		if (atomic_dec_and_test(&connection->active_ee_cnt))
			wake_up(&connection->ee_wait);
		return;
	}

	/* after we moved peer_req to done_ee,
	 * we may no longer access it,
	 * it may be freed/reused already!
	 * (as soon as we release the peer_reqs_lock) */
	type = peer_req->i.type;

	if (peer_req->flags & EE_WAS_ERROR) {
		/* In protocol != C, we usually do not send write acks.
		 * In case of a write error, send the neg ack anyways.
		 * This only applies to to application writes, not to resync. */
		if (peer_req->i.type == INTERVAL_PEER_WRITE) {
			if (!__test_and_set_bit(__EE_SEND_WRITE_ACK, &peer_req->flags))
				inc_unacked(peer_device);
		}
		drbd_set_out_of_sync(peer_device, peer_req->i.sector, peer_req->i.size);
		drbd_handle_io_error(device, DRBD_WRITE_ERROR);
	}

	spin_lock_irqsave(&connection->peer_reqs_lock, flags);
	device->writ_cnt += peer_req->i.size >> 9;
	atomic_inc(&connection->done_ee_cnt);
	list_add_tail(&peer_req->w.list, &connection->done_ee);
	if (peer_req->i.type == INTERVAL_RESYNC_WRITE && peer_req->flags & EE_TRIM) {
		LIST_HEAD(merged);
		int merged_count;

		merged_count = drbd_unmerge_discard(peer_req, &merged);
		list_splice_tail(&merged, &connection->done_ee);
		atomic_add(merged_count, &connection->done_ee_cnt);
	}
	peer_req = NULL; /* may be freed after unlock */
	spin_unlock_irqrestore(&connection->peer_reqs_lock, flags);

	/*
	 * Do not remove from the requests tree here: we did not send the
	 * Ack yet.
	 * Removed from the tree from "drbd_finish_peer_reqs" within the
	 * appropriate callback (e_end_block/e_end_resync_block) or from
	 * cleanup functions if the connection is lost.
	 */

	if (connection->cstate[NOW] == C_CONNECTED)
		queue_work(connection->ack_sender, &connection->send_acks_work);

	if (type == INTERVAL_RESYNC_WRITE)
		do_wake = atomic_dec_and_test(&connection->backing_ee_cnt);
	else
		do_wake = atomic_dec_and_test(&connection->active_ee_cnt);

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

	if (status && drbd_device_ratelimit(device, BACKEND))
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
		if (drbd_device_ratelimit(device, BACKEND))
			drbd_emerg(device, "delayed completion of aborted local request; disk-timeout may be too aggressive\n");

		if (!status)
			drbd_panic_after_delayed_completion_of_aborted_request(device);
	}

	/* to avoid recursion in __req_mod */
	if (unlikely(status)) {
		enum req_op op = bio_op(bio);
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

	/* it is legal to fail read-ahead, no drbd_handle_io_error for READ_AHEAD_COMPLETED_WITH_ERROR */
	if (what == WRITE_COMPLETED_WITH_ERROR)
		drbd_handle_io_error(device, DRBD_WRITE_ERROR);
	else if (what == READ_COMPLETED_WITH_ERROR)
		drbd_handle_io_error(device, DRBD_READ_ERROR);

	spin_lock_irqsave(&device->interval_lock, flags);
	set_bit(INTERVAL_BACKING_COMPLETED, &req->i.flags);
	if (req->local_rq_state & RQ_WRITE)
		drbd_release_conflicts(device, &req->i);
	spin_unlock_irqrestore(&device->interval_lock, flags);

	/* not req_mod(), we need irqsave here! */
	read_lock_irqsave(&device->resource->state_rwlock, flags);
	__req_mod(req, what, NULL, &m);
	read_unlock_irqrestore(&device->resource->state_rwlock, flags);
	put_ldev(device);

	if (m.bio)
		complete_master_bio(device, &m);
}

struct dagtag_find_result {
	int err;
	unsigned int node_id;
	u64 dagtag;
};

static struct dagtag_find_result find_current_dagtag(struct drbd_resource *resource)
{
	struct drbd_connection *connection;
	struct dagtag_find_result ret = { 0 };

	read_lock_irq(&resource->state_rwlock);

	if (resource->role[NOW] == R_PRIMARY) {
		/* Sending data and sending resync requests are not
		 * synchronized with each other, so our peer may need to wait
		 * until it has received more data before it can reply to this
		 * request. */
		ret.node_id = resource->res_opts.node_id;
		ret.dagtag = resource->dagtag_sector;
	} else {
		for_each_connection(connection, resource) {
			if (connection->peer_role[NOW] != R_PRIMARY)
				continue;

			/* Do not depend on a stale dagtag. */
			if (!test_bit(RECEIVED_DAGTAG, &connection->flags))
				continue;

			if (ret.dagtag) {
				if (drbd_ratelimit())
					drbd_err(resource, "Refusing to resync due to multiple remote primaries\n");
				ret.err = 1;
				break;
			} else {
				ret.node_id = connection->peer_node_id;
				ret.dagtag = atomic64_read(&connection->last_dagtag_sector);
			}
		}
	}

	read_unlock_irq(&resource->state_rwlock);

	return ret;
}

static void send_resync_request(struct drbd_peer_request *peer_req)
{
	struct drbd_peer_device *peer_device = peer_req->peer_device;
	struct drbd_connection *connection = peer_device->connection;
	struct dagtag_find_result dagtag_result;

	if (!(connection->agreed_features & DRBD_FF_RESYNC_DAGTAG) &&
			drbd_al_active(peer_device->device, peer_req->i.sector, peer_req->i.size)) {
		dynamic_drbd_dbg(peer_device,
				"Abort resync request at %llus+%u due to activity",
				(unsigned long long) peer_req->i.sector, peer_req->i.size);

		drbd_unsuccessful_resync_request(peer_req, false);
		return;
	}

	inc_rs_pending(peer_device);

	dagtag_result = find_current_dagtag(peer_device->device->resource);
	if (dagtag_result.err) {
		change_cstate(peer_device->connection, C_DISCONNECTING, CS_HARD);
		return;
	}

	if (peer_req->flags & EE_HAS_DIGEST) {
		enum drbd_packet cmd = connection->agreed_features & DRBD_FF_RESYNC_DAGTAG ?
			P_RS_CSUM_DAGTAG_REQ : P_CSUM_RS_REQUEST;

		void *digest = drbd_prepare_drequest_csum(peer_req, cmd,
				peer_req->digest->digest_size,
				dagtag_result.node_id, dagtag_result.dagtag);
		if (!digest)
			return;

		memcpy(digest, peer_req->digest->digest, peer_req->digest->digest_size);

		/* We are now finished with the digest, so we can free it.
		 * If we don't, the reference will be lost when the block_id
		 * field of the union is used for the reply. */
		peer_req->flags &= ~EE_HAS_DIGEST;
		kfree(peer_req->digest);
		peer_req->digest = NULL;

		drbd_send_command(peer_device, cmd, DATA_STREAM);
	} else {
		enum drbd_packet cmd;
		if (connection->agreed_features & DRBD_FF_RESYNC_DAGTAG)
			cmd = peer_req->flags & EE_RS_THIN_REQ ? P_RS_THIN_DAGTAG_REQ : P_RS_DAGTAG_REQ;
		else
			cmd = peer_req->flags & EE_RS_THIN_REQ ? P_RS_THIN_REQ : P_RS_DATA_REQUEST;

		drbd_send_rs_request(peer_device, cmd,
				peer_req->i.sector, peer_req->i.size, peer_req->block_id,
				dagtag_result.node_id, dagtag_result.dagtag);
	}
}

void drbd_conflict_send_resync_request(struct drbd_peer_request *peer_req)
{
	struct drbd_peer_device *peer_device = peer_req->peer_device;
	struct drbd_connection *connection = peer_req->peer_device->connection;
	struct drbd_device *device = peer_device->device;
	bool conflict;
	bool canceled;

	spin_lock_irq(&device->interval_lock);
	clear_bit(INTERVAL_SUBMIT_CONFLICT_QUEUED, &peer_req->i.flags);
	canceled = test_bit(INTERVAL_CANCELED, &peer_req->i.flags);
	conflict = drbd_find_conflict(device, &peer_req->i, CONFLICT_FLAG_IGNORE_SAME_PEER);
	if (drbd_interval_empty(&peer_req->i))
		drbd_insert_interval(&device->requests, &peer_req->i);
	if (!conflict)
		set_bit(INTERVAL_SENT, &peer_req->i.flags);
	spin_unlock_irq(&device->interval_lock);

	if (!conflict) {
		send_resync_request(peer_req);
	} else if (canceled) {
		drbd_remove_peer_req_interval(peer_req);
		drbd_free_peer_req(peer_req);
	}

	if ((!conflict || canceled) && atomic_dec_and_test(&connection->backing_ee_cnt))
		wake_up(&connection->ee_wait);
}

void drbd_csum_pages(struct crypto_shash *tfm, struct page *page, void *digest)
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
{
	struct bio_vec bvec;
	struct bvec_iter iter;
	SHASH_DESC_ON_STACK(desc, tfm);

	desc->tfm = tfm;

	crypto_shash_init(desc);

	bio_for_each_segment(bvec, bio, iter) {
		u8 *src;
		src = bvec_kmap_local(&bvec);
		crypto_shash_update(desc, src, bvec.bv_len);
		kunmap_local(src);
	}
	crypto_shash_final(desc, digest);
	shash_desc_zero(desc);
}

/* MAYBE merge common code with w_e_end_ov_req */
static int w_e_send_csum(struct drbd_work *w, int cancel)
{
	struct drbd_peer_request *peer_req = container_of(w, struct drbd_peer_request, w);
	struct drbd_peer_device *peer_device = peer_req->peer_device;
	struct drbd_connection *connection = peer_device->connection;
	int digest_size;
	int err = 0;
	struct digest_info *di;

	if (unlikely(cancel))
		goto out;

	/* Do not add to interval tree if already disconnected or resync aborted */
	if (!repl_is_sync_target(peer_device->repl_state[NOW]))
		goto out;

	if (unlikely((peer_req->flags & EE_WAS_ERROR) != 0))
		goto out;

	digest_size = crypto_shash_digestsize(peer_device->connection->csums_tfm);

	di = kmalloc(sizeof(*di) + digest_size, GFP_NOIO);
	if (!di) {
		err = -ENOMEM;
		goto out;
	}

	di->digest_size = digest_size;
	di->digest = (((char *)di)+sizeof(struct digest_info));

	drbd_csum_pages(peer_device->connection->csums_tfm, peer_req->page_chain.head, di->digest);
	/* Free pages before continuing.
	 * In case we block on congestion, we could otherwise run into
	 * some distributed deadlock, if the other side blocks on
	 * congestion as well, because our receiver blocks in
	 * drbd_alloc_pages due to pp_in_use > max_buffers. */
	drbd_free_page_chain(&peer_device->connection->transport, &peer_req->page_chain);

	/* Use the same drbd_peer_request for tracking resync request and for
	 * writing, if that is necessary. */
	peer_req->digest = di;
	peer_req->flags |= EE_HAS_DIGEST;

	atomic_inc(&connection->backing_ee_cnt);
	drbd_conflict_send_resync_request(peer_req);
	return 0;

out:
	atomic_sub(peer_req->i.size >> SECTOR_SHIFT, &peer_device->device->rs_sect_ev);
	drbd_free_peer_req(peer_req);

	if (unlikely(err))
		drbd_err(peer_device, "drbd_send_drequest(..., csum) failed\n");
	return err;
}

static int read_for_csum(struct drbd_peer_device *peer_device, sector_t sector, int size)
{
	struct drbd_connection *connection = peer_device->connection;
	struct drbd_device *device = peer_device->device;
	struct drbd_peer_request *peer_req;

	if (!get_ldev(device))
		return -EIO;

	/* Do not wait if no memory is immediately available.  */
	peer_req = drbd_alloc_peer_req(peer_device, GFP_TRY & ~__GFP_RECLAIM);
	if (!peer_req)
		goto defer;

	spin_lock_irq(&connection->peer_reqs_lock);
	list_add_tail(&peer_req->recv_order, &peer_device->resync_requests);
	peer_req->flags |= EE_ON_RECV_ORDER;
	spin_unlock_irq(&connection->peer_reqs_lock);

	if (size) {
		drbd_alloc_page_chain(&connection->transport,
			&peer_req->page_chain, DIV_ROUND_UP(size, PAGE_SIZE), GFP_TRY);
		if (!peer_req->page_chain.head)
			goto defer2;
	}
	peer_req->i.size = size;
	peer_req->i.sector = sector;
	/* This will be a resync write once we receive the data back from the
	 * peer, assuming the checksums differ. */
	peer_req->i.type = INTERVAL_RESYNC_WRITE;
	peer_req->requested_size = size;

	peer_req->w.cb = w_e_send_csum;
	peer_req->opf = REQ_OP_READ;

	atomic_inc(&connection->backing_ee_cnt);
	atomic_add(size >> 9, &device->rs_sect_ev);
	if (drbd_submit_peer_request(peer_req) == 0)
		return 0;

	/* If it failed because of ENOMEM, retry should help.  If it failed
	 * because bio_add_page failed (probably broken lower level driver),
	 * retry may or may not help.
	 * If it does not, you may need to force disconnect. */

defer2:
	drbd_free_peer_req(peer_req);
defer:
	put_ldev(device);
	return -EAGAIN;
}

static int make_one_resync_request(struct drbd_peer_device *peer_device, int discard_granularity, sector_t sector, int size)
{
	struct drbd_device *device = peer_device->device;
	struct drbd_connection *connection = peer_device->connection;
	struct drbd_peer_request *peer_req;

	/* Do not wait if no memory is immediately available.  */
	peer_req = drbd_alloc_peer_req(peer_device, GFP_TRY & ~__GFP_RECLAIM);
	if (!peer_req) {
		drbd_err(device, "Could not allocate resync request\n");
		put_ldev(device);
		return -EAGAIN;
	}

	peer_req->i.size = size;
	peer_req->i.sector = sector;
	peer_req->i.type = INTERVAL_RESYNC_WRITE;
	peer_req->requested_size = size;

	if (size == discard_granularity)
		peer_req->flags |= EE_RS_THIN_REQ;

	spin_lock_irq(&connection->peer_reqs_lock);
	list_add_tail(&peer_req->recv_order, &peer_device->resync_requests);
	peer_req->flags |= EE_ON_RECV_ORDER;
	spin_unlock_irq(&connection->peer_reqs_lock);

	atomic_inc(&connection->backing_ee_cnt);
	drbd_conflict_send_resync_request(peer_req);
	return 0;
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
		if (atomic_read(&peer_device->rs_sect_in) >= peer_device->rs_in_flight) {
			struct drbd_resource *resource = peer_device->device->resource;
			unsigned long irq_flags;
			begin_state_change(resource, &irq_flags, 0);
			peer_device->resync_active[NEW] = false;
			end_state_change(resource, &irq_flags, "resync-inactive");
		}
		break;
	}

	return 0;
}

int w_send_dagtag(struct drbd_work *w, int cancel)
{
	struct drbd_connection *connection =
		container_of(w, struct drbd_connection, send_dagtag_work);
	struct drbd_resource *resource = connection->resource;
	int err;
	u64 dagtag_sector;

	if (cancel)
		return 0;

	read_lock_irq(&resource->state_rwlock);
	dagtag_sector = connection->send_dagtag;
	/* It is OK to use the value outside the lock, because the work will be
	 * queued again if it is changed. */
	read_unlock_irq(&resource->state_rwlock);

	/* Only send if no request with a newer dagtag has been sent. This can
	 * occur if a write arrives after the state change and is processed
	 * before this work item. */
	if (dagtag_newer_eq(connection->send.current_dagtag_sector, dagtag_sector))
		return 0;

	err = drbd_send_dagtag(connection, dagtag_sector);
	if (err)
		return err;

	connection->send.current_dagtag_sector = dagtag_sector;
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

bool drbd_any_flush_pending(struct drbd_resource *resource)
{
	unsigned long flags;
	struct drbd_connection *primary_connection;
	bool any_flush_pending = false;

	spin_lock_irqsave(&resource->initiator_flush_lock, flags);
	rcu_read_lock();
	for_each_connection_rcu(primary_connection, resource) {
		if (primary_connection->pending_flush_mask) {
			any_flush_pending = true;
			break;
		}
	}
	rcu_read_unlock();
	spin_unlock_irqrestore(&resource->initiator_flush_lock, flags);

	return any_flush_pending;
}

void resync_timer_fn(struct timer_list *t)
{
	struct drbd_peer_device *peer_device = timer_container_of(peer_device, t, resync_timer);

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

	if (duration_ns < RS_MAKE_REQS_INTV_NS) {
		/* Scale sect_in so that it represents the number of sectors which
		 * would have arrived if the cycle had lasted the normal time
		 * (RS_MAKE_REQS_INTV). */
		sect_in = sect_in * RS_MAKE_REQS_INTV_NS;
		do_div(sect_in, duration_ns);
	}

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
		max_sect = (u64)pdc->c_max_rate * 2 * RS_MAKE_REQS_INTV_NS;
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

/* Calculate how many 4k sized blocks we want to resync this time.
 * Because peer nodes may have different bitmap granularity,
 * and won't be able to clear "partial bits", make sure we try to request
 * multiples of BM_BLOCK_SIZE_MAX from the peer in one go.
 * Return value is scaled to our bm_block_size.
 */
static int drbd_rs_number_requests(struct drbd_peer_device *peer_device)
{
	struct net_conf *nc;
	ktime_t duration, now;
	unsigned int sect_in;  /* Number of sectors that came in since the last turn */
	int number, mxb;
	struct drbd_bitmap *bm = peer_device->device->bitmap;

	sect_in = atomic_xchg(&peer_device->rs_sect_in, 0);
	peer_device->rs_in_flight -= sect_in;

	now = ktime_get();
	duration = ktime_sub(now, peer_device->rs_last_mk_req_kt);
	peer_device->rs_last_mk_req_kt = now;

	rcu_read_lock();
	nc = rcu_dereference(peer_device->connection->transport.net_conf);
	mxb = nc ? nc->max_buffers : 0;
	if (rcu_dereference(peer_device->rs_plan_s)->size) {
		number = drbd_rs_controller(peer_device, sect_in, ktime_to_ns(duration));
		number = sect_to_bit(number, BM_BLOCK_SHIFT_4k);
	} else {
		number = RS_MAKE_REQS_INTV * rcu_dereference(peer_device->conf)->resync_rate
			/ ((BM_BLOCK_SIZE_4k/1024) * HZ);
	}
	rcu_read_unlock();

	/* Don't have more than "max-buffers"/2 in-flight.
	 * Otherwise we may cause the remote site to stall on drbd_alloc_pages(),
	 * potentially causing a distributed deadlock on congestion during
	 * online-verify or (checksum-based) resync, if max-buffers,
	 * socket buffer sizes and resync rate settings are mis-configured.
	 * Note that "number" is in units of "bm_bytes_per_bit",
	 * mxb (as used here, and in drbd_alloc_pages on the peer) is
	 * "number of pages" (typically 4k), and "rs_in_flight" is in "sectors"
	 * (512 Byte). Convert everything to sectors and back.
	 */
	{
		int mxb_sect = mxb << (PAGE_SHIFT - 9);
		int num_sect = bit_to_sect(number, BM_BLOCK_SHIFT_4k);

		if (mxb_sect - peer_device->rs_in_flight < num_sect) {
			num_sect = mxb_sect - peer_device->rs_in_flight;
			number = sect_to_bit(num_sect, BM_BLOCK_SHIFT_4k);
		}
	}
	number = ALIGN(number, BM_BLOCK_SIZE_MAX/BM_BLOCK_SIZE_4k);
	peer_device->c_sync_rate = number * HZ * (BM_BLOCK_SIZE_4k/1024) / RS_MAKE_REQS_INTV;
	return number >> (bm->bm_block_shift - BM_BLOCK_SHIFT_4k);
}

static int resync_delay(bool request_ok, int number, int done)
{
	if (request_ok && number > 0 && done > 0) {
		/* Requests in-flight. Adjusting the standard delay to
		 * mitigate rounding and other errors, that cause 'done'
		 * to be different from the optimal 'number'.  (usually
		 * in the range of 66ms to 133ms) */
		return RS_MAKE_REQS_INTV * done / number;
	}

	return RS_MAKE_REQS_INTV;
}

void drbd_rs_all_in_flight_came_back(struct drbd_peer_device *peer_device, int rs_sect_in)
{
	unsigned int max_bio_size_kb = DRBD_MAX_BIO_SIZE / 1024;
	struct drbd_device *device = peer_device->device;
	unsigned int c_max_rate, interval, latency, m, amount_kb;
	unsigned int rs_kib_in = rs_sect_in / 2;
	ktime_t latency_kt;
	bool kickstart;

	if (get_ldev(device)) {
		max_bio_size_kb = queue_max_hw_sectors(device->rq_queue) / 2;
		put_ldev(device);
	}

	rcu_read_lock();
	c_max_rate = rcu_dereference(peer_device->conf)->c_max_rate;
	rcu_read_unlock();

	latency_kt = ktime_sub(ktime_get(), peer_device->rs_last_mk_req_kt);
	latency = nsecs_to_jiffies(ktime_to_ns(latency_kt));

	m = max_bio_size_kb > rs_kib_in ? max_bio_size_kb / rs_kib_in : 1;
	if (c_max_rate != 0)
		interval = rs_kib_in * m * HZ / c_max_rate;
	else
		interval = 0;
	/* interval holds the ideal pace in which we should request max_bio_size */

	if (peer_device->repl_state[NOW] == L_SYNC_TARGET) {
		/* Only run resync_work early if we are definitely making
		 * progress. Otherwise we might continually lock a resync
		 * extent even when all the requests are canceled. This can
		 * cause application IO to be blocked for an indefinitely long
		 * time. */
		if (test_bit(RS_REQUEST_UNSUCCESSFUL, &peer_device->flags))
			return;
	}

	amount_kb = c_max_rate / (HZ / RS_MAKE_REQS_INTV);
	kickstart = rs_kib_in < amount_kb / 2 && latency < RS_MAKE_REQS_INTV / 2;
	/* In case the latency of the link and remote IO subsystem is small and
	   the controller was clearly issuing a too small number of requests,
	   kickstart it by scheduling it immediately */

	if (kickstart || interval <= latency) {
		drbd_queue_work_if_unqueued(
			&peer_device->connection->sender_work,
			&peer_device->resync_work);
		return;
	}

	if (interval < RS_MAKE_REQS_INTV)
		mod_timer(&peer_device->resync_timer, jiffies + (interval - latency));
}

static void drbd_enable_peer_replication(struct drbd_device *device)
{
	struct drbd_resource *resource = device->resource;
	unsigned long irq_flags;
	struct drbd_peer_device *peer_device;

	begin_state_change(resource, &irq_flags, CS_VERBOSE);
	for_each_peer_device(peer_device, device)
		peer_device->peer_replication[NEW] = true;
	end_state_change(resource, &irq_flags, "enable-peer-replication");
}

/* Returns whether whole resync is finished. */
static bool drbd_resync_check_finished(struct drbd_peer_device *peer_device)
{
	struct drbd_connection *connection = peer_device->connection;
	struct drbd_device *device = peer_device->device;
	struct drbd_resource *resource = connection->resource;
	bool resync_requests_complete;
	unsigned long bitmap_weight;
	unsigned long last_resync_pass_bits;
	bool peer_replication;

	/* Test whether resync pass finished */
	if (drbd_bm_find_next(peer_device, peer_device->resync_next_bit) < DRBD_END_OF_BITMAP)
		return false;

	if (drbd_any_flush_pending(resource))
		return false;

	spin_lock_irq(&connection->peer_reqs_lock);
	resync_requests_complete = list_empty(&peer_device->resync_requests);
	spin_unlock_irq(&connection->peer_reqs_lock);

	if (!resync_requests_complete)
		return false;

	last_resync_pass_bits = peer_device->last_resync_pass_bits;
	bitmap_weight = drbd_bm_total_weight(peer_device);
	peer_device->last_resync_pass_bits = bitmap_weight;

	peer_replication = drbd_all_peer_replication(device, NOW);
	dynamic_drbd_dbg(peer_device, "Resync pass complete last:%lu out-of-sync:%lu failed:%lu replication:%s\n",
			last_resync_pass_bits, bitmap_weight, peer_device->rs_failed,
			peer_replication ? "enabled" : "disabled");

	if (!peer_replication) {
		if (peer_device->rs_failed == 0 && bitmap_weight > 0 &&
				bitmap_weight < last_resync_pass_bits / 2) {
			/* Start next pass with replication still disabled */
			peer_device->resync_next_bit = 0;
			return false;
		}

		drbd_enable_peer_replication(device);
		return false;
	}

	if (peer_device->rs_failed == 0 && bitmap_weight > 0) {
		/* Start next pass. Replication is enabled. */
		peer_device->resync_next_bit = 0;
		return false;
	}

	drbd_resync_finished(peer_device, D_MASK);
	return true;
}

static bool send_buffer_half_full(struct drbd_peer_device *peer_device)
{
	struct drbd_connection *connection = peer_device->connection;
	struct drbd_transport *transport = &connection->transport;
	bool half_full = false;

	mutex_lock(&connection->mutex[DATA_STREAM]);
	if (transport->class->ops.stream_ok(transport, DATA_STREAM)) {
		struct drbd_transport_stats transport_stats;
		int queued, sndbuf;

		transport->class->ops.stats(transport, &transport_stats);
		queued = transport_stats.send_buffer_used;
		sndbuf = transport_stats.send_buffer_size;
		if (queued > sndbuf / 2) {
			half_full = true;
			transport->class->ops.hint(transport, DATA_STREAM, NOSPACE);
		}
	} else {
		half_full = true;
	}
	mutex_unlock(&connection->mutex[DATA_STREAM]);

	return half_full;
}

static int optimal_bits_for_alignment(unsigned long bit, int bm_block_shift)
{
	int max_bio_bits = DRBD_MAX_BIO_SIZE >> bm_block_shift;

	/* under the assumption that we find a big block of out-of-sync blocks
	   in the bitmap, calculate the optimal request size so that the
	   request sizes get bigger, and each request is "perfectly" aligned.
	   (In case the backing device is a RAID5)
	   for an odd number, it returns 1.
	   for anything dividable by 2, it returns 2.
	   for 3 it returns 1 so that the next request size can be 4.
	   and so on...
	*/

	/* Only consider the lower order bits up to the size of max_bio_bits.
	 * This prevents overflows when converting to int. */
	bit = bit & (max_bio_bits - 1);

	if (bit == 0)
		return max_bio_bits;

	return 1 << __ffs(bit);
}

static int round_to_powerof_2(int value)
{
	int l2 = fls(value) - 1;
	int smaller = 1 << l2;
	int bigger = smaller << 1;

	if (value == 0)
		return 0;

	return value - smaller < bigger - value ? smaller : bigger;
}

static bool adjacent(sector_t sector1, int size, sector_t sector2)
{
	return sector1 + (size >> SECTOR_SHIFT) == sector2;
}

/* make_resync_request() - initiate resync requests as required
 *
 * Request handling flow:
 *
 *                     checksum resync
 * make_resync_request --------+
 *       |                     v
 *       |               read_for_csum
 *       |                     |
 *       |                     v
 *       |          drbd_submit_peer_request
 *       |                     |
 *       |                    ... backing device
 *       |                     |
 *       |                     v
 *       |           drbd_peer_request_endio
 *       |                     |
 *       |                     v
 *       |          drbd_endio_read_sec_final
 *       |                     |
 *       V                    ... sender_work
 * make_one_resync_request     |
 *       |                     v
 *       +---------------- w_e_send_csum
 *       |
 *       v                             conflict
 * drbd_conflict_send_resync_request -------+
 *       |                ^                 |
 *       |                |                ...
 *       |                |                 |
 *       |                |                 v
 *       v                +---- drbd_do_submit_conflict
 * send_resync_request
 *       |
 *      ... via peer
 *       |
 *       +----------------------------+
 *       |                            |
 *       v                            v
 * receive_RSDataReply      receive_rs_deallocated
 *       |                            |
 *       |                           ... using list resync_requests
 *       |                            |
 *       v                            v
 * recv_resync_read        drbd_process_rs_discards
 *       |                            |
 *       |                            v
 *       +----------------- drbd_submit_rs_discard
 *       |
 *       v                             conflict
 * drbd_conflict_submit_resync_request -----+
 *       |                ^                 |
 *       |                |                ...
 *       |                |                 |
 *       |                |                 v
 *       v                +---- drbd_do_submit_conflict
 * drbd_submit_peer_request
 *       |
 *      ... backing device
 *       |
 *       v
 * drbd_peer_request_endio
 *       |
 *       v
 * drbd_endio_write_sec_final
 *       |
 *      ... done_ee
 *       |
 *       v
 * drbd_finish_peer_reqs
 *       |
 *       v
 * e_end_resync_block
 *       |
 *       v
 * drbd_resync_request_complete
 */
static int make_resync_request(struct drbd_peer_device *peer_device, int cancel)
{
	int optimal_bits_alignment, optimal_bits_rate, discard_granularity = 0;
	int number = 0, rollback_i, size = 0, i = 0, optimal_bits;
	struct drbd_connection *connection = peer_device->connection;
	struct drbd_device *device = peer_device->device;
	struct drbd_bitmap *bm = device->bitmap;
	const sector_t capacity = get_capacity(device->vdisk);
	bool request_ok = true;
	unsigned long bit;
	sector_t sector, prev_sector = 0;
	unsigned int bm_block_shift;
	unsigned int peer_bm_block_shift;
	unsigned int bits_per_peer_bit;

	if (unlikely(cancel))
		return 0;

	if (test_bit(SYNC_TARGET_TO_BEHIND, &peer_device->flags)) {
		/* If a P_RS_CANCEL_AHEAD on control socket overtook the
		 * already queued data and state change to Ahead/Behind,
		 * don't add more resync requests, just wait it out. */
		drbd_info_ratelimit(peer_device, "peer pulled ahead during resync\n");
		return 0;
	}

	if (drbd_resync_check_finished(peer_device))
		return 0;

	if (!get_ldev(device)) {
		/* Since we only need to access device->rsync a
		   get_ldev_if_state(device,D_FAILED) would be sufficient, but
		   to continue resync with a broken disk makes no sense at
		   all */
		drbd_err(device, "Disk broke down during resync!\n");
		return 0;
	}
	bm_block_shift = bm->bm_block_shift;
	peer_bm_block_shift = peer_device->bm_block_shift;
	if (peer_bm_block_shift > bm_block_shift)
		bits_per_peer_bit = 1<<(peer_bm_block_shift - bm_block_shift);
	else
		bits_per_peer_bit = 1; // or maybe even only a partial bit ;-)

	if (send_buffer_half_full(peer_device)) {
		/* We still want to reschedule ourselves, so do not return. */
		goto skip_request;
	}

	if (connection->agreed_features & DRBD_FF_THIN_RESYNC) {
		rcu_read_lock();
		discard_granularity = rcu_dereference(device->ldev->disk_conf)->rs_discard_granularity;
		rcu_read_unlock();
	}

	number = drbd_rs_number_requests(peer_device);
	if (number < discard_granularity >> bm_block_shift)
		number = discard_granularity >> bm_block_shift;

	/*
	 * Drain resync requests when we jump back to avoid conflicts that are
	 * resolved in an arbitrary order, leading to an unexpected ordering of
	 * requests being completed.
	 */
	if (test_bit(RS_REQUEST_UNSUCCESSFUL, &peer_device->flags) &&
			peer_device->rs_in_flight > 0) {
		/*
		 * The rs_in_flight counter does not include discards waiting
		 * to be merged. Hence we may jump back while there are
		 * discards waiting to be merged. In this situation, we may
		 * make a resync request that conflicts with a discard. Allow
		 * the discard to be merged here so that the conflict is
		 * resolved.
		 */
		drbd_process_rs_discards(peer_device, false);
		goto skip_request;
	}

	/* don't let rs_sectors_came_in() re-schedule us "early"
	 * just because the first reply came "fast", ... */
	peer_device->rs_in_flight += bm_bit_to_sect(device->bitmap, number);
	if (peer_device->bm_block_shift > bm_block_shift)
		bits_per_peer_bit = 1<<(peer_device->bm_block_shift - bm_block_shift);
	else
		bits_per_peer_bit = 1; // or maybe even only a partial bit ;-)

	clear_bit(RS_REQUEST_UNSUCCESSFUL, &peer_device->flags);
	for (; i < number; i += bits_per_peer_bit) {
		int err;

		/* If we are aborting the requests or the peer is canceling
		 * them, there is no need to flood the connection with
		 * requests. Back off now. */
		if (i > 0 && test_bit(RS_REQUEST_UNSUCCESSFUL, &peer_device->flags)) {
			request_ok = false;
			goto request_done;
		}

		if ((number - i) < discard_granularity >> bm_block_shift)
			goto request_done;

		bit  = drbd_bm_find_next(peer_device, peer_device->resync_next_bit);
		if (bit == DRBD_END_OF_BITMAP) {
			peer_device->resync_next_bit = drbd_bm_bits(device);
			goto request_done;
		}

		bit = ALIGN_DOWN(bit, bits_per_peer_bit);
		sector = bm_bit_to_sect(bm, bit);

		if (drbd_rs_c_min_rate_throttle(peer_device)) {
			peer_device->resync_next_bit = bit;
			goto request_done;
		}

		if (adjacent(prev_sector, size, sector) && (number - i) < size >> bm_block_shift) {
			/* When making requests in an out-of-sync area, ensure that the size
			   of successive requests does not decrease. This allows the next
			   make_resync_request call to start with optimal alignment. */
			goto request_done;
		}

		prev_sector = sector;
		size = bm_block_size(bm) * bits_per_peer_bit;
		optimal_bits_alignment = optimal_bits_for_alignment(bit, bm_block_shift);
		optimal_bits_rate = round_to_powerof_2(number - i);
		optimal_bits = min(optimal_bits_alignment, optimal_bits_rate) - 1;

		/* try to find some adjacent bits. */
		rollback_i = i;
		while (optimal_bits-- > 0) {
			if (discard_granularity && size == discard_granularity)
				break;

			if (drbd_bm_count_bits(device, peer_device->bitmap_index,
					       bit + bits_per_peer_bit,
					       bit + bits_per_peer_bit * 2 - 1) == 0)
				break;
			size += bm_block_size(bm) * bits_per_peer_bit;
			bit += bits_per_peer_bit;
			i += bits_per_peer_bit;
		}

		/* set the offset to start the next drbd_bm_find_next from */
		peer_device->resync_next_bit = bit + bits_per_peer_bit;

		/* adjust very last sectors, in case we are oddly sized */
		if (sector + (size>>9) > capacity)
			size = (capacity-sector)<<9;

		if (peer_device->use_csums)
			err = read_for_csum(peer_device, sector, size);
		else
			err = make_one_resync_request(peer_device, discard_granularity, sector, size);

		switch (err) {
		case -EIO: /* Disk failure */
			put_ldev(device);
			return -EIO;
		case -EAGAIN: /* allocation failed, or ldev busy */
			set_bit(RS_REQUEST_UNSUCCESSFUL, &peer_device->flags);
			peer_device->resync_next_bit = bm_sect_to_bit(bm, sector);
			i = rollback_i;
			goto request_done;
		case 0:
			/* everything ok */
			break;
		default:
			BUG();
		}
	}

request_done:
	/* ... but do a correction, in case we had to break/goto request_done; */
	peer_device->rs_in_flight -= (number - i) * bm_sect_per_bit(bm);

	if (peer_device->resync_next_bit >= drbd_bm_bits(device)) {
		/*
		 * Last resync request sent in this pass. There will be no
		 * replies for subsequent sectors so discard merging should
		 * stop here.
		 */
		drbd_last_resync_request(peer_device, false);
	}

skip_request:
	/* Always reschedule ourselves as a form of polling to detect the end of a resync pass. */
	mod_timer(&peer_device->resync_timer, jiffies + resync_delay(request_ok, number, i));

	if (i > 0 && request_ok) {
		int rs_sect_in = atomic_read(&peer_device->rs_sect_in);

		if (rs_sect_in >= peer_device->rs_in_flight) {
			/*
			 * In case replies were received before correction to
			 * rs_in_flight, consider whether to schedule ourselves
			 * early.
			 */
			drbd_rs_all_in_flight_came_back(peer_device, rs_sect_in);
		}
	}
	put_ldev(device);
	return 0;
}

static void send_ov_request(struct drbd_peer_request *peer_req)
{
	struct drbd_peer_device *peer_device = peer_req->peer_device;
	struct dagtag_find_result dagtag_result;
	enum drbd_packet cmd = peer_device->connection->agreed_features & DRBD_FF_RESYNC_DAGTAG ?
		P_OV_DAGTAG_REQ : P_OV_REQUEST;

	inc_rs_pending(peer_device);

	dagtag_result = find_current_dagtag(peer_device->device->resource);
	if (dagtag_result.err) {
		change_cstate(peer_device->connection, C_DISCONNECTING, CS_HARD);
		return;
	}

	drbd_send_rs_request(peer_device, cmd,
			peer_req->i.sector, peer_req->i.size, peer_req->block_id,
			dagtag_result.node_id, dagtag_result.dagtag);
}

static void drbd_conflict_send_ov_request(struct drbd_peer_request *peer_req)
{
	struct drbd_peer_device *peer_device = peer_req->peer_device;
	struct drbd_device *device = peer_device->device;

	spin_lock_irq(&device->interval_lock);
	if (drbd_find_conflict(device, &peer_req->i, 0))
		set_bit(INTERVAL_CONFLICT, &peer_req->i.flags);
	drbd_insert_interval(&device->requests, &peer_req->i);
	set_bit(INTERVAL_SENT, &peer_req->i.flags);
	/* Mark as submitted now, since OV requests do not have a second
	 * conflict resolution stage when the reply is received. */
	set_bit(INTERVAL_SUBMITTED, &peer_req->i.flags);
	spin_unlock_irq(&device->interval_lock);

	/* If there were conflicts we will skip the block. However, we send a
	 * request anyway because the protocol doesn't include any way to mark
	 * a block as skipped without having sent any request. */
	send_ov_request(peer_req);
}

/* make_ov_request() - initiate online verify requests as required
 *
 * Request handling flow:
 *
 * make_ov_request
 *        |
 *        v
 * drbd_conflict_send_ov_request
 *        |
 *        v
 * send_ov_request
 *        |
 *       ... via peer
 *        |
 *        v
 * receive_dagtag_ov_reply
 *        |
 *        v
 * receive_common_ov_reply
 *        |
 *        v              dagtag waiting
 * drbd_peer_resync_read --------------+
 *        |                            |
 *        |                           ... dagtag_wait_ee
 *        |                            |
 *        |                            v
 *        +--------------- release_dagtag_wait
 *        |
 *        v
 * drbd_conflict_submit_peer_read
 *        |
 *        v
 * drbd_submit_peer_request
 *        |
 *       ... backing device
 *        |
 *        v
 * drbd_peer_request_endio
 *        |
 *        v
 * drbd_endio_read_sec_final
 *        |
 *       ... sender_work
 *        |
 *        v
 * w_e_end_ov_reply
 */
static int make_ov_request(struct drbd_peer_device *peer_device, int cancel)
{
	struct drbd_device *device = peer_device->device;
	struct drbd_bitmap *bm = device->bitmap;
	struct drbd_connection *connection = peer_device->connection;
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
	peer_device->rs_in_flight += bm_bit_to_sect(bm, number);
	for (i = 0; i < number; i++) {
		struct drbd_peer_request *peer_req;

		if (sector >= capacity)
			break;

		/* We check for "finished" only in the reply path:
		 * w_e_end_ov_reply().
		 * We need to send at least one request out. */
		stop_sector_reached = sector > peer_device->ov_start_sector
			&& verify_can_do_stop_sector(peer_device)
			&& sector >= peer_device->ov_stop_sector;
		if (stop_sector_reached)
			break;

		if (drbd_rs_c_min_rate_throttle(peer_device))
			break;

		size = bm_block_size(bm);
		if (sector + (size>>9) > capacity)
			size = (capacity-sector)<<9;

		/* Do not wait if no memory is immediately available.  */
		peer_req = drbd_alloc_peer_req(peer_device, GFP_TRY & ~__GFP_RECLAIM);
		if (!peer_req) {
			drbd_err(device, "Could not allocate online verify request\n");
			put_ldev(device);
			return 0;
		}

		peer_req->i.size = size;
		peer_req->i.sector = sector;
		peer_req->i.type = INTERVAL_OV_READ_SOURCE;

		spin_lock_irq(&connection->peer_reqs_lock);
		list_add_tail(&peer_req->recv_order, &connection->peer_reads);
		peer_req->flags |= EE_ON_RECV_ORDER;
		spin_unlock_irq(&connection->peer_reqs_lock);

		drbd_conflict_send_ov_request(peer_req);

		sector += bm_sect_per_bit(bm);
	}
	/* ... but do a correction, in case we had to break; ... */
	peer_device->rs_in_flight -= bm_bit_to_sect(bm, number-i);
	peer_device->ov_position = sector;
	if (stop_sector_reached)
		return 1;
	/* ... and in case that raced with the receiver,
	 * reschedule ourselves right now */
	if (i > 0 && atomic_read(&peer_device->rs_sect_in) >= peer_device->rs_in_flight)
		drbd_queue_work_if_unqueued(
			&peer_device->connection->sender_work,
			&peer_device->resync_work);
	else
		mod_timer(&peer_device->resync_timer, jiffies + resync_delay(true, number, i));
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

	if (!cancel)
		drbd_resync_finished(rfw->pdw.peer_device, rfw->new_peer_disk_state);
	kfree(rfw);

	return 0;
}

static long ping_timeout(struct drbd_connection *connection)
{
	struct net_conf *nc;
	long timeout;

	rcu_read_lock();
	nc = rcu_dereference(connection->transport.net_conf);
	timeout = nc->ping_timeo * HZ / 10;
	rcu_read_unlock();

	return timeout;
}

static int send_ping_peer(struct drbd_connection *connection)
{
	bool was_pending = test_and_set_bit(PING_PENDING, &connection->flags);
	int err = 0;

	if (!was_pending) {
		err = drbd_send_ping(connection);
		if (err)
			change_cstate(connection, C_NETWORK_FAILURE, CS_HARD);
	}

	return err;
}

void drbd_ping_peer(struct drbd_connection *connection)
{
	long r, timeout = ping_timeout(connection);
	int err;

	err = send_ping_peer(connection);
	if (err)
		return;

	r = wait_event_timeout(connection->resource->state_wait,
			       !test_bit(PING_PENDING, &connection->flags) ||
			       connection->cstate[NOW] < C_CONNECTED,
			       timeout);
	if (r > 0)
		return;

	drbd_warn(connection, "PingAck did not arrive in time\n");
	change_cstate(connection, C_NETWORK_FAILURE, CS_HARD);
}

/* caller needs to hold rcu_read_lock, state_rwlock, adm_mutex or conf_update */
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
				end_state_change_locked(device->resource, "resync-again");
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
			atomic64_set(&lost_peer->last_dagtag_sector,
				connection->after_reconciliation.dagtag_sector);

		kref_put(&lost_peer->kref, drbd_destroy_connection);
	}

	connection->after_reconciliation.lost_node_id = -1;
}

static void try_to_get_resynced_from_primary(struct drbd_device *device)
{
	struct drbd_resource *resource = device->resource;
	struct drbd_peer_device *peer_device;
	struct drbd_connection *connection;

	read_lock_irq(&resource->state_rwlock);
	for_each_peer_device(peer_device, device) {
		if (peer_device->connection->peer_role[NEW] == R_PRIMARY &&
		    peer_device->disk_state[NEW] == D_UP_TO_DATE)
			goto found;
	}
	peer_device = NULL;
found:
	read_unlock_irq(&resource->state_rwlock);

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
	drbd_start_resync(peer_device, L_SYNC_TARGET, "resync-from-primary");
}

static void queue_resync_finished(struct drbd_peer_device *peer_device, enum drbd_disk_state new_peer_disk_state)
{
	struct drbd_connection *connection = peer_device->connection;
	struct resync_finished_work *rfw;

	rfw = kmalloc(sizeof(*rfw), GFP_ATOMIC);
	if (!rfw) {
		drbd_err(peer_device, "Warn failed to kmalloc(dw).\n");
		return;
	}

	rfw->pdw.w.cb = w_resync_finished;
	rfw->pdw.peer_device = peer_device;
	rfw->new_peer_disk_state = new_peer_disk_state;
	drbd_queue_work(&connection->sender_work, &rfw->pdw.w);
}

void drbd_resync_finished(struct drbd_peer_device *peer_device,
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
	int bm_block_shift = device->last_bm_block_shift;

	if (repl_state[NOW] == L_SYNC_SOURCE || repl_state[NOW] == L_PAUSED_SYNC_S) {
		/* Make sure all queued w_update_peers() executed. */
		if (current == device->resource->worker.task) {
			queue_resync_finished(peer_device, new_peer_disk_state);
			return;
		} else {
			drbd_flush_workqueue(&device->resource->work);
		}
	}

	if (!down_write_trylock(&device->uuid_sem)) {
		if (current == device->resource->worker.task) {
			queue_resync_finished(peer_device, new_peer_disk_state);
			return;
		} else {
			down_write(&device->uuid_sem);
		}
	}

	dt = (jiffies - peer_device->rs_start - peer_device->rs_paused) / HZ;
	if (dt <= 0)
		dt = 1;
	db = peer_device->rs_total;
	/* adjust for verify start and stop sectors, respective reached position */
	if (repl_state[NOW] == L_VERIFY_S || repl_state[NOW] == L_VERIFY_T)
		db -= atomic64_read(&peer_device->ov_left);

	dbdt = bit_to_kb(db/dt, bm_block_shift);
	peer_device->rs_paused /= HZ;

	if (!get_ldev(device)) {
		up_write(&device->uuid_sem);
		goto out;
	}

	drbd_ping_peer(connection);

	write_lock_irq(&device->resource->state_rwlock);
	begin_state_change_locked(device->resource, CS_VERBOSE);
	old_repl_state = repl_state[NOW];

	verify_done = (repl_state[NOW] == L_VERIFY_S || repl_state[NOW] == L_VERIFY_T);

	/* This protects us against multiple calls (that can happen in the presence
	   of application IO), and against connectivity loss just before we arrive here. */
	if (peer_device->repl_state[NOW] <= L_ESTABLISHED)
		goto out_unlock;

	/*
	 * This protects us against a race with the peer when finishing a
	 * resync at the same time as entering Ahead-Behind mode.
	 */
	if (peer_device->repl_state[NOW] == L_BEHIND)
		goto out_unlock;

	peer_device->resync_active[NEW] = false;
	__change_repl_state(peer_device, L_ESTABLISHED);

	aborted = device->disk_state[NOW] == D_OUTDATED && new_peer_disk_state == D_INCONSISTENT;
	{
	char tmp[sizeof(" but 01234567890123456789 4k blocks skipped")] = "";
	if (verify_done && peer_device->ov_skipped)
		snprintf(tmp, sizeof(tmp), " but %lu %lluk blocks skipped",
			peer_device->ov_skipped, bit_to_kb(1, bm_block_shift));
	drbd_info(peer_device, "%s %s%s (total %lu sec; paused %lu sec; %lu K/sec)\n",
		  verify_done ? "Online verify" : "Resync",
		  aborted ? "aborted" : "done", tmp,
		  dt + peer_device->rs_paused, peer_device->rs_paused, dbdt);
	}

	n_oos = drbd_bm_total_weight(peer_device);

	if (repl_state[NOW] == L_VERIFY_S || repl_state[NOW] == L_VERIFY_T) {
		if (n_oos) {
			drbd_alert(peer_device, "Online verify found %lu %lluk blocks out of sync!\n",
			      n_oos, bit_to_kb(1, bm_block_shift));
			khelper_cmd = "out-of-sync";
		}
	} else {
		if (!aborted && peer_device->rs_failed == 0 && n_oos != 0)
			drbd_warn(peer_device, "expected n_oos:%lu to be 0\n", n_oos);

		if (repl_state[NOW] == L_SYNC_TARGET || repl_state[NOW] == L_PAUSED_SYNC_T)
			khelper_cmd = "after-resync-target";

		if (peer_device->use_csums && peer_device->rs_total) {
			const unsigned long s = peer_device->rs_same_csum;
			const unsigned long t = peer_device->rs_total;
			const int ratio =
				(t == 0)     ? 0 :
			(t < 100000) ? ((s*100)/t) : (s/(t/100));
			drbd_info(peer_device, "%u %% had equal checksums, eliminated: %lluK; "
			     "transferred %lluK total %lluK\n",
			     ratio,
			     bit_to_kb(peer_device->rs_same_csum, bm_block_shift),
			     bit_to_kb(peer_device->rs_total - peer_device->rs_same_csum,
					bm_block_shift),
			     bit_to_kb(peer_device->rs_total, bm_block_shift));
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

			if (stable_resync && test_bit(UUIDS_RECEIVED, &peer_device->flags)) {
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
				if (!test_bit(UUIDS_RECEIVED, &peer_device->flags))
					drbd_err(peer_device, "BUG: uuids were not received!\n");

				if (test_bit(UNSTABLE_RESYNC, &peer_device->flags))
					drbd_info(peer_device, "Peer was unstable during resync\n");
			}
		} else if (repl_state[NOW] == L_SYNC_SOURCE || repl_state[NOW] == L_PAUSED_SYNC_S) {
			if (new_peer_disk_state != D_MASK)
				__change_peer_disk_state(peer_device, new_peer_disk_state);
			if (peer_device->connection->agreed_pro_version < 110) {
				drbd_uuid_set_bitmap(peer_device, 0UL);
				drbd_print_uuids(peer_device, "updated UUIDs");
			}
		}
	}

out_unlock:
	end_state_change_locked(device->resource, "resync-finished");

	put_ldev(device);

	peer_device->rs_total  = 0;
	peer_device->rs_failed = 0;
	peer_device->rs_paused = 0;

	if (old_repl_state == L_SYNC_TARGET || old_repl_state == L_PAUSED_SYNC_T)
		target_m |= NODE_MASK(peer_device->node_id);
	else if (old_repl_state == L_SYNC_SOURCE || old_repl_state == L_PAUSED_SYNC_S)
		source_m |= NODE_MASK(peer_device->node_id);

	resync_again(device, source_m, target_m);
	write_unlock_irq(&device->resource->state_rwlock);
	up_write(&device->uuid_sem);
	if (connection->after_reconciliation.lost_node_id != -1)
		after_reconciliation_resync(connection);

	/* Potentially send final P_PEERS_IN_SYNC. */
	drbd_queue_update_peers(peer_device,
			peer_device->last_peers_in_sync_end, get_capacity(device->vdisk));

out:
	/* reset start sector, if we reached end of device */
	if (verify_done && atomic64_read(&peer_device->ov_left) == 0)
		peer_device->ov_start_sector = 0;

	drbd_md_sync_if_dirty(device);

	if (khelper_cmd)
		drbd_maybe_khelper(device, connection, khelper_cmd);

	if (try_to_get_resynced_from_primary_flag)
		try_to_get_resynced_from_primary(device);
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
		err = 0;
		goto out;
	}

	if (likely((peer_req->flags & EE_WAS_ERROR) == 0)) {
		err = drbd_send_block(peer_device, P_DATA_REPLY, peer_req);
	} else {
		drbd_err_ratelimit(peer_device, "Sending NegDReply. sector=%llus.\n",
			    (unsigned long long)peer_req->i.sector);

		err = drbd_send_ack(peer_device, P_NEG_DREPLY, peer_req);
	}
	if (unlikely(err))
		drbd_err(peer_device, "drbd_send_block() failed\n");

out:
	dec_unacked(peer_device);
	drbd_free_peer_req(peer_req);

	return err;
}

void
drbd_resync_read_req_mod(struct drbd_peer_request *peer_req, enum drbd_interval_flags bit_to_set)
{
	const unsigned long done_mask = 1UL << INTERVAL_SENT | 1UL << INTERVAL_RECEIVED;
	struct drbd_peer_device *peer_device = peer_req->peer_device;
	unsigned long nflags, oflags, new_flag;

	new_flag = 1UL << bit_to_set;
	if (!(new_flag & done_mask))
		drbd_err(peer_device, "BUG: %s: Unexpected flag 0x%lx\n", __func__, new_flag);

	do {
		oflags = READ_ONCE(peer_req->i.flags);
		nflags = oflags | new_flag;
	} while (cmpxchg(&peer_req->i.flags, oflags, nflags) != oflags);

	if (new_flag & oflags)
		drbd_err(peer_device, "BUG: %s: Flag 0x%lx already set\n", __func__, new_flag);

	if ((nflags & done_mask) == done_mask) {
		drbd_remove_peer_req_interval(peer_req);
		drbd_free_peer_req(peer_req);
	}
}

static bool all_zero(struct drbd_peer_request *peer_req)
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

static bool al_resync_extent_active(struct drbd_device *device, sector_t sector, unsigned int size)
{
	sector_t resync_extent_sector = sector & ~LEGACY_BM_EXT_SECT_MASK;
	sector_t end_sector = sector + (size >> SECTOR_SHIFT);
	sector_t resync_extent_end_sector =
		(end_sector + LEGACY_BM_EXT_SECT_MASK) & ~LEGACY_BM_EXT_SECT_MASK;
	return drbd_al_active(device,
			resync_extent_sector,
			(resync_extent_end_sector - resync_extent_sector) << SECTOR_SHIFT);
}

static int drbd_rs_reply(struct drbd_peer_device *peer_device, struct drbd_peer_request *peer_req, bool *expect_ack)
{
	struct drbd_connection *connection = peer_device->connection;
	struct drbd_device *device = peer_device->device;
	int err;
	bool eq = false;

	if (peer_req->flags & EE_HAS_DIGEST) {
		struct digest_info *di = peer_req->digest;
		int digest_size;
		void *digest = NULL;

		/* quick hack to try to avoid a race against reconfiguration.
		 * a real fix would be much more involved,
		 * introducing more locking mechanisms */
		if (connection->csums_tfm) {
			digest_size = crypto_shash_digestsize(connection->csums_tfm);
			D_ASSERT(device, digest_size == di->digest_size);
			digest = kmalloc(digest_size, GFP_NOIO);
			if (digest) {
				drbd_csum_pages(connection->csums_tfm, peer_req->page_chain.head, digest);
				eq = !memcmp(digest, di->digest, digest_size);
				kfree(digest);
			}
		}

		peer_req->flags &= ~EE_HAS_DIGEST; /* This peer request no longer has a digest pointer */
		kfree(di);
	}

	if (eq) {
		drbd_set_in_sync(peer_device, peer_req->i.sector, peer_req->i.size);
		/* rs_same_csums unit is BM_BLOCK_SIZE */
		peer_device->rs_same_csum += peer_req->i.size >> device->ldev->md.bm_block_shift;
		err = drbd_send_ack(peer_device, P_RS_IS_IN_SYNC, peer_req);
	} else {
		inc_rs_pending(peer_device);
		/*
		 * If we send back as P_RS_DEALLOCATED,
		 * this is overestimating "in-flight" accounting.
		 * But needed to be properly balanced with
		 * the atomic_sub() in got_RSWriteAck.
		 */
		atomic_add(peer_req->i.size >> 9, &connection->rs_in_flight);

		spin_lock_irq(&connection->peer_reqs_lock);
		list_add_tail(&peer_req->w.list, &connection->resync_ack_ee);
		spin_unlock_irq(&connection->peer_reqs_lock);

		if (peer_req->flags & EE_RS_THIN_REQ && all_zero(peer_req)) {
			err = drbd_send_rs_deallocated(peer_device, peer_req);
		} else {
			err = drbd_send_block(peer_device, P_RS_DATA_REPLY, peer_req);
		}
		*expect_ack = true;

		drbd_free_page_chain(&connection->transport, &peer_req->page_chain);

		drbd_resync_read_req_mod(peer_req, INTERVAL_SENT);
		peer_req = NULL;
	}

	return err;
}

/**
 * w_e_end_rsdata_req() - Reply to a resync request.
 * @w:		work object.
 * @cancel:	The connection is being closed
 *
 * Worker callback to send P_RS_DATA_REPLY or a related packet after completing
 * a resync read.
 *
 * Return: Error code or 0 on success.
 */
int w_e_end_rsdata_req(struct drbd_work *w, int cancel)
{
	struct drbd_peer_request *peer_req = container_of(w, struct drbd_peer_request, w);
	struct drbd_peer_device *peer_device = peer_req->peer_device;
	struct drbd_connection *connection = peer_device->connection;
	int err;
	bool expect_ack = false;

	if (unlikely(cancel) || connection->cstate[NOW] < C_CONNECTED) {
		drbd_remove_peer_req_interval(peer_req);
		drbd_free_peer_req(peer_req);
		dec_unacked(peer_device);
		return 0;
	}

	if (peer_device->repl_state[NOW] == L_AHEAD) {
		err = drbd_send_ack(peer_device, P_RS_CANCEL, peer_req);
	} else if (likely((peer_req->flags & EE_WAS_ERROR) == 0)) {
		if (unlikely(peer_device->disk_state[NOW] < D_INCONSISTENT)) {
			if (connection->agreed_features & DRBD_FF_RESYNC_DAGTAG) {
				drbd_err_ratelimit(peer_device,
						"Sending P_RS_CANCEL, partner DISKLESS!\n");
				err = drbd_send_ack(peer_device, P_RS_CANCEL, peer_req);
			} else {
				/*
				 * A peer that does not support DRBD_FF_RESYNC_DAGTAG does not
				 * expect to receive P_RS_CANCEL after losing its disk.
				 */
				drbd_err_ratelimit(peer_device,
						"Not sending resync reply, partner DISKLESS!\n");
				err = 0;
			}
		} else if (connection->agreed_pro_version >= 110 &&
				!(connection->agreed_features & DRBD_FF_RESYNC_DAGTAG) &&
				al_resync_extent_active(peer_device->device,
					peer_req->i.sector, peer_req->i.size)) {
			/* DRBD versions without DRBD_FF_RESYNC_DAGTAG lock
			 * 128MiB "resync extents" in the activity log whenever
			 * they make resync requests. Some of these versions
			 * also lock activity lock extents when receiving
			 * P_DATA. In particular, DRBD 9.0 and 9.1. This can
			 * cause a deadlock if we send resync replies in these
			 * extents as follows:
			 * * Node is SyncTarget towards us
			 * * Node locks a resync extent and sends P_RS_DATA_REQUEST
			 * * Node receives P_DATA write in this extent; write
			 *   waits for resync extent to be unlocked
			 * * Node receives P_BARRIER (protocol A); receiver
			 *   thread blocks waiting for write to complete
			 * * We reply to P_RS_DATA_REQUEST, but it is never
			 *   processed because receiver thread is blocked
			 *
			 * Break the deadlock by canceling instead. This is
			 * sent on the control socket so it will be processed. */
			dynamic_drbd_dbg(peer_device,
					"Cancel resync request at %llus+%u due to activity",
					(unsigned long long) peer_req->i.sector, peer_req->i.size);

			err = drbd_send_ack(peer_device, P_RS_CANCEL, peer_req);
		} else {
			err = drbd_rs_reply(peer_device, peer_req, &expect_ack);

			/* If expect_ack is true, peer_req may already have been freed. */
			if (expect_ack)
				peer_req = NULL;
		}
	} else {
		drbd_err_ratelimit(peer_device, "Sending NegRSDReply. sector %llus.\n",
		    (unsigned long long)peer_req->i.sector);

		err = drbd_send_ack(peer_device, P_NEG_RS_DREPLY, peer_req);

		/* update resync data with failure */
		drbd_rs_failed_io(peer_device, peer_req->i.sector, peer_req->i.size);
	}

	dec_unacked(peer_device);

	if (!expect_ack) {
		drbd_remove_peer_req_interval(peer_req);
		drbd_free_peer_req(peer_req);
	}

	if (unlikely(err))
		drbd_err(peer_device, "Sending resync reply failed\n");
	return err;
}

int w_e_end_ov_req(struct drbd_work *w, int cancel)
{
	struct drbd_peer_request *peer_req = container_of(w, struct drbd_peer_request, w);
	struct drbd_peer_device *peer_device = peer_req->peer_device;
	struct drbd_device *device = peer_device->device;
	struct drbd_connection *connection = peer_device->connection;
	int digest_size;
	void *digest;
	sector_t sector = peer_req->i.sector;
	unsigned int size = peer_req->i.size;
	struct dagtag_find_result dagtag_result;
	int err = 0;
	enum drbd_packet cmd = connection->agreed_features & DRBD_FF_RESYNC_DAGTAG ?
		P_OV_DAGTAG_REPLY : P_OV_REPLY;

	if (unlikely(cancel) || connection->cstate[NOW] < C_CONNECTED)
		goto out;

	if (!(connection->agreed_features & DRBD_FF_RESYNC_DAGTAG) &&
		al_resync_extent_active(peer_device->device, peer_req->i.sector, peer_req->i.size)) {
		/* A peer that does not support DRBD_FF_RESYNC_DAGTAG expects
		 * online verify to be exclusive with 128MiB "resync extents"
		 * in the activity log. If such a verify source sends a request
		 * but we receive an overlapping write before the request then
		 * we will read newer data for the verify transaction than the
		 * source did. So we may detect spurious out-of-sync blocks.
		 *
		 * In addition, we may trigger a deadlock in such a peer by
		 * sending a reply if it is waiting for writes to drain due to
		 * a P_BARRIER packet. See w_e_end_rsdata_req for details.
		 *
		 * Prevent these issues by canceling instead.
		 */
		dynamic_drbd_dbg(peer_device,
				"Cancel online verify request at %llus+%u due to activity",
				(unsigned long long) peer_req->i.sector, peer_req->i.size);

		spin_lock_irq(&device->interval_lock);
		set_bit(INTERVAL_CONFLICT, &peer_req->i.flags);
		spin_unlock_irq(&device->interval_lock);
	}

	if (test_bit(INTERVAL_CONFLICT, &peer_req->i.flags)) {
		if (connection->agreed_pro_version < 110) {
			if (drbd_ratelimit())
				drbd_warn(peer_device, "Verify request conflicts but cannot cancel, "
						"peer may report spurious out-of-sync\n");
		} else {
			drbd_verify_skipped_block(peer_device, sector, size);
			verify_progress(peer_device, sector, size);
			drbd_send_ack(peer_device, P_RS_CANCEL, peer_req);
			goto out;
		}
	}

	dagtag_result = find_current_dagtag(peer_device->device->resource);
	if (dagtag_result.err)
		goto out;

	set_bit(INTERVAL_SENT, &peer_req->i.flags);

	digest_size = crypto_shash_digestsize(peer_device->connection->verify_tfm);
	/* FIXME if this allocation fails, online verify will not terminate! */
	digest = drbd_prepare_drequest_csum(peer_req, cmd, digest_size,
			dagtag_result.node_id, dagtag_result.dagtag);
	if (!digest) {
		err = -ENOMEM;
		goto out;
	}

	if (!(peer_req->flags & EE_WAS_ERROR))
		drbd_csum_pages(peer_device->connection->verify_tfm,
				peer_req->page_chain.head, digest);
	else
		memset(digest, 0, digest_size);

	/* Free pages before send.
	 * In case we block on congestion, we could otherwise run into
	 * some distributed deadlock, if the other side blocks on
	 * congestion as well, because our receiver blocks in
	 * drbd_alloc_pages due to pp_in_use > max_buffers. */
	drbd_free_page_chain(&peer_device->connection->transport, &peer_req->page_chain);

	inc_rs_pending(peer_device);

	err = drbd_send_command(peer_device, cmd, DATA_STREAM);
	if (err)
		goto out_rs_pending;

	dec_unacked(peer_device);
	return 0;

out_rs_pending:
	dec_rs_pending(peer_device);
out:
	drbd_remove_peer_req_interval(peer_req);
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

	unsigned long ov_left = atomic64_dec_return(&peer_device->ov_left);

	/* let's advance progress step marks only for every other megabyte */
	if ((ov_left & 0x1ff) == 0)
		drbd_advance_rs_marks(peer_device, ov_left);

	if (ov_left == 0 || stop_sector_reached)
		drbd_peer_device_post_work(peer_device, RS_DONE);
}

static bool digest_equal(struct drbd_peer_request *peer_req)
{
	struct drbd_peer_device *peer_device = peer_req->peer_device;
	struct drbd_device *device = peer_device->device;
	struct digest_info *di;
	void *digest;
	int digest_size;
	bool eq = false;

	di = peer_req->digest;

	digest_size = crypto_shash_digestsize(peer_device->connection->verify_tfm);
	digest = kmalloc(digest_size, GFP_NOIO);
	if (digest) {
		drbd_csum_pages(peer_device->connection->verify_tfm, peer_req->page_chain.head, digest);

		D_ASSERT(device, digest_size == di->digest_size);
		eq = !memcmp(digest, di->digest, digest_size);
		kfree(digest);
	}

	return eq;
}

int w_e_end_ov_reply(struct drbd_work *w, int cancel)
{
	struct drbd_peer_request *peer_req = container_of(w, struct drbd_peer_request, w);
	struct drbd_peer_device *peer_device = peer_req->peer_device;
	struct drbd_connection *connection = peer_device->connection;
	sector_t sector = peer_req->i.sector;
	unsigned int size = peer_req->i.size;
	u64 block_id = peer_req->block_id;
	enum ov_result result;
	bool al_conflict = false;
	int err;

	if (unlikely(cancel)) {
		drbd_remove_peer_req_interval(peer_req);
		drbd_free_peer_req(peer_req);
		dec_unacked(peer_device);
		return 0;
	}

	if (!(connection->agreed_features & DRBD_FF_RESYNC_DAGTAG) &&
		al_resync_extent_active(peer_device->device, peer_req->i.sector, peer_req->i.size)) {
		/* A peer that does not support DRBD_FF_RESYNC_DAGTAG expects
		 * online verify to be exclusive with 128MiB "resync extents"
		 * in the activity log. We may have received an overlapping
		 * write before issuing this read, which the peer did not have
		 * at the time of its read. So we may detect spurious
		 * out-of-sync blocks.
		 *
		 * Prevent this by skipping instead.
		 */
		dynamic_drbd_dbg(peer_device,
				"Skip online verify block at %llus+%u due to activity",
				(unsigned long long) peer_req->i.sector, peer_req->i.size);

		al_conflict = true;
	}

	if (test_bit(INTERVAL_CONFLICT, &peer_req->i.flags) || al_conflict) {
		/* DRBD versions without DRBD_FF_RESYNC_DAGTAG do not know about
		 * OV_RESULT_SKIP, but they treat it the same as OV_RESULT_IN_SYNC which is
		 * the best we can do here anyway. */
		result = OV_RESULT_SKIP;
		drbd_verify_skipped_block(peer_device, sector, size);
	} else if (likely((peer_req->flags & EE_WAS_ERROR) == 0) && digest_equal(peer_req)) {
		result = OV_RESULT_IN_SYNC;
		ov_out_of_sync_print(peer_device);
	} else {
		result = OV_RESULT_OUT_OF_SYNC;
		drbd_ov_out_of_sync_found(peer_device, sector, size);
	}

	/* Free peer_req and pages before send.
	 * In case we block on congestion, we could otherwise run into
	 * some distributed deadlock, if the other side blocks on
	 * congestion as well, because our receiver blocks in
	 * drbd_alloc_pages due to pp_in_use > max_buffers. */
	drbd_remove_peer_req_interval(peer_req);
	drbd_free_peer_req(peer_req);
	peer_req = NULL;

	err = drbd_send_ov_result(peer_device, sector, size, block_id, result);

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
		if (end_state_change_locked(other_device->resource, "resync-after") !=
				SS_NOTHING_TO_DO)
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
		if (end_state_change_locked(other_device->resource, "resync-after") !=
				SS_NOTHING_TO_DO)
			changed = true;
	}
	rcu_read_unlock();
	return changed;
}

void resume_next_sg(struct drbd_device *device)
{
	lock_all_resources();
	while (drbd_resume_next(device))
		; /* Iterate if some state changed. */
	unlock_all_resources();
}

void suspend_other_sg(struct drbd_device *device)
{
	lock_all_resources();
	while (drbd_pause_after(device))
		; /* Iterate if some state changed. */
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
	struct gendisk *disk = peer_device->device->ldev->backing_bdev->bd_disk;
	struct fifo_buffer *plan;

	atomic_set(&peer_device->rs_sect_in, 0);
	atomic_set(&peer_device->device->rs_sect_ev, 0);  /* FIXME: ??? */
	peer_device->rs_last_mk_req_kt = ktime_get();
	peer_device->rs_in_flight = 0;
	peer_device->rs_last_events = (int)part_stat_read_accum(disk->part0, sectors);

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
	struct drbd_peer_device *peer_device = timer_container_of(peer_device, t,
			start_resync_timer);
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
	/* Postpone resync if there is still activity from a previous resync
	 * pending. Also postpone the transition from Ahead to SyncSource if
	 * there is any activity on this peer device. */
	if (atomic_read(&peer_device->rs_pending_cnt) ||
			(peer_device->repl_state[NOW] == L_AHEAD &&
			 atomic_read(&peer_device->unacked_cnt))) {
		drbd_warn(peer_device, "postponing start_resync ...\n");
		mod_timer(&peer_device->start_resync_timer, jiffies + HZ/10);
		return;
	}

	drbd_start_resync(peer_device, peer_device->start_resync_side, "postponed-resync");
	clear_bit(AHEAD_TO_SYNC_SOURCE, &peer_device->flags);
}

static void handle_congestion(struct drbd_peer_device *peer_device)
{
	struct drbd_resource *resource = peer_device->device->resource;
	unsigned long irq_flags;
	struct net_conf *nc;
	enum drbd_on_congestion on_congestion;

	rcu_read_lock();
	nc = rcu_dereference(peer_device->connection->transport.net_conf);
	if (nc) {
		on_congestion = nc->on_congestion;

		begin_state_change(resource, &irq_flags, CS_VERBOSE | CS_HARD);
		/* congestion may have cleared since it was detected */
		if (atomic_read(&peer_device->connection->ap_in_flight) > 0) {
			if (on_congestion == OC_PULL_AHEAD)
				__change_repl_state(peer_device, L_AHEAD);
			else if (on_congestion == OC_DISCONNECT)
				__change_cstate(peer_device->connection, C_DISCONNECTING);
		}
		end_state_change(resource, &irq_flags, "congestion");
	}
	rcu_read_unlock();

	clear_bit(HANDLING_CONGESTION, &peer_device->flags);
}

/**
 * drbd_start_resync() - Start the resync process
 * @peer_device: The DRBD peer device to start the resync on.
 * @side: Direction of the resync; which side am I? Either L_SYNC_SOURCE or
 * 	  L_SYNC_TARGET.
 * @tag: State change tag to print in status messages.
 *
 * This function might bring you directly into one of the
 * C_PAUSED_SYNC_* states.
 */
void drbd_start_resync(struct drbd_peer_device *peer_device, enum drbd_repl_state side,
		const char *tag)
{
	struct drbd_device *device = peer_device->device;
	struct drbd_connection *connection = peer_device->connection;
	enum drbd_disk_state finished_resync_pdsk = D_UNKNOWN;
	enum drbd_repl_state repl_state;
	int r;

	read_lock_irq(&device->resource->state_rwlock);
	repl_state = peer_device->repl_state[NOW];
	read_unlock_irq(&device->resource->state_rwlock);
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
		mod_timer(&peer_device->start_resync_timer, jiffies + HZ/5);
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
	r = end_state_change_locked(device->resource, tag);
	repl_state = peer_device->repl_state[NOW];

	if (repl_state < L_ESTABLISHED)
		r = SS_UNKNOWN_ERROR;

	if (r == SS_SUCCESS)
		drbd_pause_after(device);

	unlock_all_resources();
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
			drbd_resync_finished(peer_device, D_MASK);
		} else if (is_sync_state(peer_device, NOW)) {
			drbd_resync_finished(peer_device, D_MASK);
		}
	}

	/* update timestamp, in case it took a while to write out stuff */
	peer_device->rs_last_writeout = jiffies;
	put_ldev(device);
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
			}
		}
	}

	drbd_md_sync_if_dirty(device);
	drbd_bm_free(device);
	change_disk_state(device, D_DISKLESS, CS_HARD, "go-diskless", NULL);
}

static int do_md_sync(struct drbd_device *device)
{
	drbd_warn(device, "md_sync_timer expired! Worker calls drbd_md_sync().\n");
	drbd_md_sync(device);
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

static bool all_responded(struct drbd_resource *resource)
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
		if (test_bit(PING_PENDING, &connection->flags)) {
			all_responded = false;
			continue;
		} else {
			clear_bit(CHECKING_PEER, &connection->flags);
		}
	}
	rcu_read_unlock();

	return all_responded;
}

void drbd_check_peers(struct drbd_resource *resource)
{
	struct drbd_connection *connection;
	long t, timeo = LONG_MAX;
	unsigned long start;
	bool check_ongoing;
	u64 im;

	check_ongoing = test_and_set_bit(CHECKING_PEERS, &resource->flags);
	if (check_ongoing) {
		wait_event(resource->state_wait,
			   !test_bit(CHECKING_PEERS, &resource->flags));
		return;
	}

	start = jiffies;
	for_each_connection_ref(connection, im, resource) {
		if (connection->cstate[NOW] < C_CONNECTED)
			continue;
		set_bit(CHECKING_PEER, &connection->flags);
		send_ping_peer(connection);
		t = ping_timeout(connection);
		if (t < timeo)
			timeo = t;
	}

	while (!wait_event_timeout(resource->state_wait, all_responded(resource), timeo)) {
		unsigned long waited = jiffies - start;

		timeo = LONG_MAX;
		rcu_read_lock();
		for_each_connection_rcu(connection, resource) {
			if (!test_bit(CHECKING_PEER, &connection->flags))
				continue;
			t = ping_timeout(connection);
			if (waited >= t) {
				drbd_warn(connection, "peer failed to send PingAck in time\n");
				change_cstate(connection, C_NETWORK_FAILURE, CS_HARD);
				clear_bit(CHECKING_PEER, &connection->flags);
				continue;
			}
			if (t - waited < timeo)
				timeo = t - waited;
		}
		rcu_read_unlock();
	}

	clear_bit(CHECKING_PEERS, &resource->flags);
	wake_up_all(&resource->state_wait);
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
	if (test_bit(HANDLE_CONGESTION, &todo))
		handle_congestion(peer_device);
}

#define DRBD_DEVICE_WORK_MASK	\
	((1UL << GO_DISKLESS)	\
	|(1UL << MD_SYNC)	\
	|(1UL << MAKE_NEW_CUR_UUID)\
	)

#define DRBD_PEER_DEVICE_WORK_MASK	\
	((1UL << RS_START)		\
	|(1UL << RS_LAZY_BM_WRITE)	\
	|(1UL << RS_PROGRESS)		\
	|(1UL << RS_DONE)		\
	|(1UL << HANDLE_CONGESTION)     \
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

static bool dequeue_work_batch(struct drbd_work_queue *queue, struct list_head *work_list)
{
	spin_lock_irq(&queue->q_lock);
	list_splice_tail_init(&queue->q, work_list);
	spin_unlock_irq(&queue->q_lock);
	return !list_empty(work_list);
}

static struct drbd_request *__next_request_for_connection(
		struct drbd_connection *connection)
{
	struct drbd_request *req;

	list_for_each_entry_rcu(req, &connection->resource->transfer_log, tl_requests) {
		unsigned s = req->net_rq_state[connection->peer_node_id];

		if (likely(s & RQ_NET_QUEUED))
			return req;
	}
	return NULL;
}

static struct drbd_request *tl_next_request_for_connection(
		struct drbd_connection *connection, bool wait_ready)
{
	if (connection->todo.req_next == NULL)
		connection->todo.req_next = __next_request_for_connection(connection);

	if (connection->todo.req_next == NULL) {
		connection->todo.req = NULL;
	} else {
		unsigned int s = connection->todo.req_next->net_rq_state[connection->peer_node_id];

		if (likely((s & RQ_NET_READY) || !wait_ready)) {
			connection->todo.req = connection->todo.req_next;
			connection->send.seen_dagtag_sector = connection->todo.req->dagtag_sector;
		} else {
			/* Leave the request in "req_next" until it is ready */
			connection->todo.req = NULL;
		}
	}

	/*
	 * Advancement of todo.req_next happens in advance_conn_req_next(),
	 * called from mod_rq_state()
	 */

	return connection->todo.req;
}

static void maybe_send_state_after_ahead(struct drbd_connection *connection)
{
	struct drbd_peer_device *peer_device;
	int vnr;

	rcu_read_lock();
	idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
		if (test_and_clear_bit(SEND_STATE_AFTER_AHEAD, &peer_device->flags)) {
			peer_device->todo.was_sending_out_of_sync = false;
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
	rcu_read_lock();
	tl_next_request_for_connection(connection, true);

	/* FIXME can we get rid of this additional lock? */
	spin_lock_irq(&connection->sender_work.q_lock);
	list_splice_tail_init(&connection->sender_work.q, &connection->todo.work_list);
	spin_unlock_irq(&connection->sender_work.q_lock);
	rcu_read_unlock();

	return connection->todo.req
		|| need_unplug(connection)
		|| !list_empty(&connection->todo.work_list);
}

static bool drbd_send_barrier_next_oos(struct drbd_connection *connection)
{
	if (!connection->todo.req_next)
		return false;

	return connection->todo.req_next->net_rq_state[connection->peer_node_id]
		& RQ_NET_PENDING_OOS;
}

static void wait_for_sender_todo(struct drbd_connection *connection)
{
	struct drbd_resource *resource = connection->resource;
	DEFINE_WAIT(wait);
	struct net_conf *nc;
	int uncork, cork;
	bool got_something = 0;

	got_something = check_sender_todo(connection);
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
		if (check_sender_todo(connection) || signal_pending(current)) {
			break;
		}

		/* We found nothing new to do, no to-be-communicated request,
		 * no other work item.  We may still need to close the last
		 * epoch.  Next incoming request epoch will be connection ->
		 * current transfer log epoch number.  If that is different
		 * from the epoch of the last request we communicated, we want
		 * to send the epoch separating barrier now.
		 */
		send_barrier = should_send_barrier(connection,
					atomic_read(&resource->current_tle_nr));

		if (send_barrier) {
			/* Ensure that we read the most recent
			 * resource->dagtag_sector value. */
			smp_rmb();
			/* If a request is currently being submitted it may not
			 * have been picked up by this sender, even though it
			 * belongs to the old epoch. Ensure that we are
			 * up-to-date with the most recently submitted dagtag
			 * to ensure that we do not send a barrier early in
			 * this case. If there is such a request then this
			 * sender will be woken, so it is OK to schedule().
			 *
			 * If we have found a request that is
			 * RQ_NET_PENDING_OOS, but not yet RQ_NET_READY, then
			 * we also need to send a barrier.
			 */
			if (dagtag_newer_eq(connection->send.seen_dagtag_sector,
						READ_ONCE(resource->dagtag_sector))
					|| drbd_send_barrier_next_oos(connection)) {
				finish_wait(&connection->sender_work.q_wait, &wait);
				maybe_send_barrier(connection,
						connection->send.current_epoch_nr + 1);
				continue;
			}
		}

		if (test_and_clear_bit(SEND_STATE_AFTER_AHEAD_C, &connection->flags)) {
			finish_wait(&connection->sender_work.q_wait, &wait);
			maybe_send_state_after_ahead(connection);
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

static int process_one_request(struct drbd_connection *connection)
{
	struct bio_and_error m;
	struct drbd_request *req = connection->todo.req;
	struct drbd_device *device = req->device;
	struct drbd_peer_device *peer_device =
			conn_peer_device(connection, device->vnr);
	unsigned s = req->net_rq_state[peer_device->node_id];
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

			if (peer_device->todo.was_sending_out_of_sync) {
				clear_bit(SEND_STATE_AFTER_AHEAD, &peer_device->flags);
				peer_device->todo.was_sending_out_of_sync = false;
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
			if (!peer_device->todo.was_sending_out_of_sync) {
				peer_device->todo.was_sending_out_of_sync = true;
				drbd_send_current_state(peer_device);
			}

			/* When this flag is not set, sending OOS may be skipped */
			if (s & RQ_NET_PENDING_OOS)
				err = drbd_send_out_of_sync(peer_device,
						req->i.sector, req->i.size);
			/* This event has the appropriate effect even if OOS skipped or failed */
			what = OOS_HANDED_TO_NETWORK;
		}
	} else {
		maybe_send_barrier(connection, req->epoch);
		err = drbd_send_drequest(peer_device,
				req->i.sector, req->i.size, (unsigned long)req);
		what = err ? SEND_FAILED : HANDED_OVER_TO_NETWORK;
	}

	read_lock_irq(&connection->resource->state_rwlock);
	__req_mod(req, what, peer_device, &m);
	read_unlock_irq(&connection->resource->state_rwlock);

	check_sender_todo(connection);

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
	} else if (list_empty(&connection->todo.work_list)) {
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
		rcu_read_lock();
		tl_next_request_for_connection(connection, false);
		rcu_read_unlock();
	}
	while (connection->todo.req) {
		struct bio_and_error m;
		struct drbd_request *req = connection->todo.req;
		struct drbd_device *device = req->device;
		peer_device = conn_peer_device(connection, device->vnr);

		read_lock_irq(&connection->resource->state_rwlock);
		__req_mod(req, SEND_CANCELED, peer_device, &m);
		read_unlock_irq(&connection->resource->state_rwlock);
		if (m.bio)
			complete_master_bio(device, &m);

		rcu_read_lock();
		tl_next_request_for_connection(connection, false);
		rcu_read_unlock();
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
			bool w, d, p;

			update_worker_timing_details(resource, dequeue_work_batch);
			wait_event_interruptible(resource->work.q_wait,
				(w = dequeue_work_batch(&resource->work, &work_list),
				 d = test_and_clear_bit(DEVICE_WORK_PENDING, &resource->flags),
				 p = test_and_clear_bit(PEER_DEVICE_WORK_PENDING, &resource->flags),
				 w || d || p));

			if (p) {
				update_worker_timing_details(resource, do_unqueued_peer_device_work);
				do_unqueued_peer_device_work(resource);
			}

			if (d) {
				update_worker_timing_details(resource, do_unqueued_device_work);
				do_unqueued_device_work(resource);
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
