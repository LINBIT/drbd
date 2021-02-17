// SPDX-License-Identifier: GPL-2.0-or-later
/*
   drbd_receiver.c

   This file is part of DRBD by Philipp Reisner and Lars Ellenberg.

   Copyright (C) 2001-2008, LINBIT Information Technologies GmbH.
   Copyright (C) 1999-2008, Philipp Reisner <philipp.reisner@linbit.com>.
   Copyright (C) 2002-2008, Lars Ellenberg <lars.ellenberg@linbit.com>.

 */


#include <linux/module.h>

#include <linux/uaccess.h>
#include <net/sock.h>

#include <linux/drbd.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/in.h>
#include <linux/mm.h>
#include <linux/memcontrol.h>
#include <linux/mm_inline.h>
#include <linux/slab.h>
#include <linux/pkt_sched.h>
#include <uapi/linux/sched/types.h>
#define __KERNEL_SYSCALLS__
#include <linux/unistd.h>
#include <linux/vmalloc.h>
#include <linux/random.h>
#include <net/ipv6.h>
#include <linux/scatterlist.h>
#include <linux/part_stat.h>

#include "drbd_int.h"
#include "drbd_protocol.h"
#include "drbd_req.h"
#include "drbd_vli.h"

#define PRO_FEATURES (DRBD_FF_TRIM|DRBD_FF_THIN_RESYNC|DRBD_FF_WSAME|DRBD_FF_WZEROES)

struct flush_work {
	struct drbd_work w;
	struct drbd_epoch *epoch;
};

enum epoch_event {
	EV_PUT,
	EV_GOT_BARRIER_NR,
	EV_BARRIER_DONE,
	EV_BECAME_LAST,
	EV_CLEANUP = 32, /* used as flag */
};

enum finish_epoch {
	FE_STILL_LIVE,
	FE_DESTROYED,
	FE_RECYCLED,
};

enum resync_reason {
	AFTER_UNSTABLE,
	DISKLESS_PRIMARY,
};

enum sync_strategy {
	UNDETERMINED,
	NO_SYNC,
	SYNC_SOURCE_IF_BOTH_FAILED,
	SYNC_SOURCE_USE_BITMAP,
	SYNC_SOURCE_SET_BITMAP,
	SYNC_SOURCE_COPY_BITMAP,
	SYNC_TARGET_IF_BOTH_FAILED,
	SYNC_TARGET_USE_BITMAP,
	SYNC_TARGET_SET_BITMAP,
	SYNC_TARGET_CLEAR_BITMAP,
	SPLIT_BRAIN_AUTO_RECOVER,
	SPLIT_BRAIN_DISCONNECT,
	UNRELATED_DATA,
	RETRY_CONNECT,
	REQUIRES_PROTO_91,
	REQUIRES_PROTO_96,
};

struct sync_descriptor {
	char * const name;
	int required_protocol;
	bool is_split_brain;
	bool is_sync_source;
	bool is_sync_target;
	int resync_peer_preference;
	enum sync_strategy full_sync_equivalent;
};

static const struct sync_descriptor sync_descriptors[] = {
	[UNDETERMINED] = {
		.name = "?",
	},
	[NO_SYNC] = {
		.name = "no-sync",
		.resync_peer_preference = 5,
	},
	[SYNC_SOURCE_IF_BOTH_FAILED] = {
		.name = "source-if-both-failed",
		.is_sync_source = true,
	},
	[SYNC_SOURCE_USE_BITMAP] = {
		.name = "source-use-bitmap",
		.is_sync_source = true,
		.full_sync_equivalent = SYNC_SOURCE_SET_BITMAP,
	},
	[SYNC_SOURCE_SET_BITMAP] = {
		.name = "source-set-bitmap",
		.is_sync_source = true,
	},
	[SYNC_SOURCE_COPY_BITMAP] = {
		.name = "source-copy-other-bitmap",
		.is_sync_source = true,
	},
	[SYNC_TARGET_IF_BOTH_FAILED] = {
		.name = "target-if-both-failed",
		.is_sync_target = true,
		.resync_peer_preference = 4,
	},
	[SYNC_TARGET_USE_BITMAP] = {
		.name = "target-use-bitmap",
		.is_sync_target = true,
		.full_sync_equivalent = SYNC_TARGET_SET_BITMAP,
		.resync_peer_preference = 3,
	},
	[SYNC_TARGET_SET_BITMAP] = {
		.name = "target-set-bitmap",
		.is_sync_target = true,
		.resync_peer_preference = 2,
	},
	[SYNC_TARGET_CLEAR_BITMAP] = {
		.name = "target-clear-bitmap",
		.is_sync_target = true,
		.resync_peer_preference = 1,
	},
	[SPLIT_BRAIN_AUTO_RECOVER] = {
		.name = "split-brain-auto-recover",
		.is_split_brain = true,
	},
	[SPLIT_BRAIN_DISCONNECT] = {
		.name = "split-brain-disconnect",
		.is_split_brain = true,
	},
	[UNRELATED_DATA] = {
		.name = "unrelated-data",
	},
	[RETRY_CONNECT] = {
		.name = "retry-connect",
	},
	[REQUIRES_PROTO_91] = {
		.name = "requires-proto-91",
		.required_protocol = 91,
	},
	[REQUIRES_PROTO_96] = {
		.name = "requires-proto-96",
		.required_protocol = 96,
	},
};

int drbd_do_features(struct drbd_connection *connection);
int drbd_do_auth(struct drbd_connection *connection);
static void conn_disconnect(struct drbd_connection *connection);

static enum finish_epoch drbd_may_finish_epoch(struct drbd_connection *, struct drbd_epoch *, enum epoch_event);
static int e_end_block(struct drbd_work *, int);
static void cleanup_unacked_peer_requests(struct drbd_connection *connection);
static void cleanup_peer_ack_list(struct drbd_connection *connection);
static u64 node_ids_to_bitmap(struct drbd_device *device, u64 node_ids);
static int process_twopc(struct drbd_connection *, struct twopc_reply *, struct packet_info *, unsigned long);
static void drbd_resync(struct drbd_peer_device *, enum resync_reason) __must_hold(local);
static void drbd_unplug_all_devices(struct drbd_connection *connection);
static int decode_header(struct drbd_connection *, void *, struct packet_info *);
static void check_resync_source(struct drbd_device *device, u64 weak_nodes);
static void destroy_peer_ack_req(struct kref *kref);

static const struct sync_descriptor strategy_descriptor(enum sync_strategy strategy)
{
	if (strategy < 0 || strategy > sizeof(sync_descriptors) / sizeof(struct sync_descriptor))
		BUG();
	return sync_descriptors[strategy];
}

static bool is_strategy_determined(enum sync_strategy strategy)
{
	return strategy == NO_SYNC ||
			strategy_descriptor(strategy).is_sync_source ||
			strategy_descriptor(strategy).is_sync_target;
}

static struct drbd_epoch *previous_epoch(struct drbd_connection *connection, struct drbd_epoch *epoch)
{
	struct drbd_epoch *prev;
	spin_lock(&connection->epoch_lock);
	prev = list_entry(epoch->list.prev, struct drbd_epoch, list);
	if (prev == epoch || prev == connection->current_epoch)
		prev = NULL;
	spin_unlock(&connection->epoch_lock);
	return prev;
}

/*
 * some helper functions to deal with single linked page lists,
 * page->private being our "next" pointer.
 */

/* If at least n pages are linked at head, get n pages off.
 * Otherwise, don't modify head, and return NULL.
 * Locking is the responsibility of the caller.
 */
static struct page *page_chain_del(struct page **head, int n)
{
	struct page *page;
	struct page *tmp;

	BUG_ON(!n);
	BUG_ON(!head);

	page = *head;

	if (!page)
		return NULL;

	while (page) {
		tmp = page_chain_next(page);
		set_page_chain_offset(page, 0);
		set_page_chain_size(page, 0);
		if (--n == 0)
			break; /* found sufficient pages */
		if (tmp == NULL)
			/* insufficient pages, don't use any of them. */
			return NULL;
		page = tmp;
	}

	/* add end of list marker for the returned list */
	set_page_chain_next(page, NULL);
	/* actual return value, and adjustment of head */
	page = *head;
	*head = tmp;
	return page;
}

/* may be used outside of locks to find the tail of a (usually short)
 * "private" page chain, before adding it back to a global chain head
 * with page_chain_add() under a spinlock. */
static struct page *page_chain_tail(struct page *page, int *len)
{
	struct page *tmp;
	int i = 1;
	while ((tmp = page_chain_next(page)))
		++i, page = tmp;
	if (len)
		*len = i;
	return page;
}

static int page_chain_free(struct page *page)
{
	struct page *tmp;
	int i = 0;
	page_chain_for_each_safe(page, tmp) {
		set_page_chain_next_offset_size(page, NULL, 0, 0);
		put_page(page);
		++i;
	}
	return i;
}

static void page_chain_add(struct page **head,
		struct page *chain_first, struct page *chain_last)
{
#if 1
	struct page *tmp;
	tmp = page_chain_tail(chain_first, NULL);
	BUG_ON(tmp != chain_last);
#endif

	/* add chain to head */
	set_page_chain_next(chain_last, *head);
	*head = chain_first;
}

static struct page *__drbd_alloc_pages(struct drbd_resource *resource, unsigned int number, gfp_t gfp_mask)
{
	struct page *page = NULL;
	struct page *tmp = NULL;
	unsigned int i = 0;

	/* Yes, testing drbd_pp_vacant outside the lock is racy.
	 * So what. It saves a spin_lock. */
	if (resource->pp_vacant >= number) {
		spin_lock(&resource->pp_lock);
		page = page_chain_del(&resource->pp_pool, number);
		if (page)
			resource->pp_vacant -= number;
		spin_unlock(&resource->pp_lock);
		if (page)
			return page;
	}

	for (i = 0; i < number; i++) {
		tmp = alloc_page(gfp_mask);
		if (!tmp)
			break;
		set_page_chain_next_offset_size(tmp, page, 0, 0);
		page = tmp;
	}

	if (i == number)
		return page;

	/* Not enough pages immediately available this time.
	 * No need to jump around here, drbd_alloc_pages will retry this
	 * function "soon". */
	if (page) {
		tmp = page_chain_tail(page, NULL);
		spin_lock(&resource->pp_lock);
		page_chain_add(&resource->pp_pool, page, tmp);
		resource->pp_vacant += i;
		spin_unlock(&resource->pp_lock);
	}
	return NULL;
}

static void rs_sectors_came_in(struct drbd_peer_device *peer_device, int size)
{
	int rs_sect_in = atomic_add_return(size >> 9, &peer_device->rs_sect_in);

	/* In case resync runs faster than anticipated, run the resync_work early */
	if (rs_sect_in >= peer_device->rs_in_flight)
		drbd_queue_work_if_unqueued(
			&peer_device->connection->sender_work,
			&peer_device->resync_work);
}

static void reclaim_finished_net_peer_reqs(struct drbd_connection *connection,
					   struct list_head *to_be_freed)
{
	struct drbd_peer_request *peer_req, *tmp;

	/* The EEs are always appended to the end of the list. Since
	   they are sent in order over the wire, they have to finish
	   in order. As soon as we see the first not finished we can
	   stop to examine the list... */

	list_for_each_entry_safe(peer_req, tmp, &connection->net_ee, w.list) {
		if (drbd_peer_req_has_active_page(peer_req))
			break;
		list_move(&peer_req->w.list, to_be_freed);
	}
}

static void drbd_reclaim_net_peer_reqs(struct drbd_connection *connection)
{
	LIST_HEAD(reclaimed);
	struct drbd_peer_request *peer_req, *t;
	struct drbd_resource *resource = connection->resource;

	spin_lock_irq(&resource->req_lock);
	reclaim_finished_net_peer_reqs(connection, &reclaimed);
	spin_unlock_irq(&resource->req_lock);

	list_for_each_entry_safe(peer_req, t, &reclaimed, w.list)
		drbd_free_net_peer_req(peer_req);
}

/**
 * drbd_alloc_pages() - Returns @number pages, retries forever (or until signalled)
 * @device:	DRBD device.
 * @number:	number of pages requested
 * @gfp_mask:	how to allocate and whether to loop until we succeed
 *
 * Tries to allocate number pages, first from our own page pool, then from
 * the kernel.
 * Possibly retry until DRBD frees sufficient pages somewhere else.
 *
 * If this allocation would exceed the max_buffers setting, we throttle
 * allocation (schedule_timeout) to give the system some room to breathe.
 *
 * We do not use max-buffers as hard limit, because it could lead to
 * congestion and further to a distributed deadlock during online-verify or
 * (checksum based) resync, if the max-buffers, socket buffer sizes and
 * resync-rate settings are mis-configured.
 *
 * Returns a page chain linked via (struct drbd_page_chain*)&page->lru.
 */
struct page *drbd_alloc_pages(struct drbd_transport *transport, unsigned int number,
			      gfp_t gfp_mask)
{
	struct drbd_connection *connection =
		container_of(transport, struct drbd_connection, transport);
	struct drbd_resource *resource = connection->resource;
	struct page *page = NULL;
	DEFINE_WAIT(wait);
	unsigned int mxb;

	rcu_read_lock();
	mxb = rcu_dereference(transport->net_conf)->max_buffers;
	rcu_read_unlock();

	if (atomic_read(&connection->pp_in_use) < mxb)
		page = __drbd_alloc_pages(resource, number, gfp_mask & ~__GFP_RECLAIM);

	/* Try to keep the fast path fast, but occasionally we need
	 * to reclaim the pages we lent to the network stack. */
	if (page && atomic_read(&connection->pp_in_use_by_net) > 512)
		drbd_reclaim_net_peer_reqs(connection);

	while (page == NULL) {
		prepare_to_wait(&resource->pp_wait, &wait, TASK_INTERRUPTIBLE);

		drbd_reclaim_net_peer_reqs(connection);

		if (atomic_read(&connection->pp_in_use) < mxb) {
			page = __drbd_alloc_pages(resource, number, gfp_mask);
			if (page)
				break;
		}

		if (!(gfp_mask & __GFP_RECLAIM))
			break;

		if (signal_pending(current)) {
			drbd_warn(connection, "drbd_alloc_pages interrupted!\n");
			break;
		}

		if (schedule_timeout(HZ/10) == 0)
			mxb = UINT_MAX;
	}
	finish_wait(&resource->pp_wait, &wait);

	if (page)
		atomic_add(number, &connection->pp_in_use);
	return page;
}

/* Must not be used from irq, as that may deadlock: see drbd_alloc_pages.
 * Is also used from inside an other spin_lock_irq(&resource->req_lock);
 * Either links the page chain back to the global pool,
 * or returns all pages to the system. */
void drbd_free_pages(struct drbd_transport *transport, struct page *page, int is_net)
{
	struct drbd_connection *connection =
		container_of(transport, struct drbd_connection, transport);
	struct drbd_resource *resource = connection->resource;
	atomic_t *a = is_net ? &connection->pp_in_use_by_net : &connection->pp_in_use;
	int i;

	if (page == NULL)
		return;

	if (resource->pp_vacant > DRBD_MAX_BIO_SIZE/PAGE_SIZE)
		i = page_chain_free(page);
	else {
		struct page *tmp;
		tmp = page_chain_tail(page, &i);
		spin_lock(&resource->pp_lock);
		page_chain_add(&resource->pp_pool, page, tmp);
		resource->pp_vacant += i;
		spin_unlock(&resource->pp_lock);
	}
	i = atomic_sub_return(i, a);
	if (i < 0)
		drbd_warn(connection, "ASSERTION FAILED: %s: %d < 0\n",
			is_net ? "pp_in_use_by_net" : "pp_in_use", i);
	wake_up(&resource->pp_wait);
}

/*
You need to hold the req_lock:
 _drbd_wait_ee_list_empty()

You must not have the req_lock:
 drbd_free_peer_req()
 drbd_alloc_peer_req()
 drbd_free_peer_reqs()
 drbd_ee_fix_bhs()
 drbd_finish_peer_reqs()
 drbd_clear_done_ee()
 drbd_wait_ee_list_empty()
*/

/* normal: payload_size == request size (bi_size)
 * w_same: payload_size == logical_block_size
 * trim: payload_size == 0 */
struct drbd_peer_request *
drbd_alloc_peer_req(struct drbd_peer_device *peer_device, gfp_t gfp_mask) __must_hold(local)
{
	struct drbd_device *device = peer_device->device;
	struct drbd_peer_request *peer_req;

	if (drbd_insert_fault(device, DRBD_FAULT_AL_EE))
		return NULL;

	peer_req = mempool_alloc(&drbd_ee_mempool, gfp_mask & ~__GFP_HIGHMEM);
	if (!peer_req) {
		if (!(gfp_mask & __GFP_NOWARN))
			drbd_err(device, "%s: allocation failed\n", __func__);
		return NULL;
	}

	memset(peer_req, 0, sizeof(*peer_req));
	INIT_LIST_HEAD(&peer_req->w.list);
	drbd_clear_interval(&peer_req->i);
	INIT_LIST_HEAD(&peer_req->recv_order);
	INIT_LIST_HEAD(&peer_req->wait_for_actlog);
	peer_req->submit_jif = jiffies;
	peer_req->peer_device = peer_device;

	return peer_req;
}

void __drbd_free_peer_req(struct drbd_peer_request *peer_req, int is_net)
{
	struct drbd_peer_device *peer_device = peer_req->peer_device;

	might_sleep();
	if (peer_req->flags & EE_HAS_DIGEST)
		kfree(peer_req->digest);
	D_ASSERT(peer_device, atomic_read(&peer_req->pending_bios) == 0);
	D_ASSERT(peer_device, drbd_interval_empty(&peer_req->i));
	drbd_free_page_chain(&peer_device->connection->transport, &peer_req->page_chain, is_net);
	mempool_free(peer_req, &drbd_ee_mempool);
}

int drbd_free_peer_reqs(struct drbd_resource *resource, struct list_head *list, bool is_net_ee)
{
	LIST_HEAD(work_list);
	struct drbd_peer_request *peer_req, *t;
	int count = 0;

	spin_lock_irq(&resource->req_lock);
	list_splice_init(list, &work_list);
	spin_unlock_irq(&resource->req_lock);

	list_for_each_entry_safe(peer_req, t, &work_list, w.list) {
		__drbd_free_peer_req(peer_req, is_net_ee);
		count++;
	}
	return count;
}

/*
 * See also comments in _req_mod(,BARRIER_ACKED) and receive_Barrier.
 */
static int drbd_finish_peer_reqs(struct drbd_connection *connection)
{
	LIST_HEAD(work_list);
	LIST_HEAD(reclaimed);
	struct drbd_peer_request *peer_req, *t;
	int err = 0;
	int n = 0;

	spin_lock_irq(&connection->resource->req_lock);
	reclaim_finished_net_peer_reqs(connection, &reclaimed);
	list_splice_init(&connection->done_ee, &work_list);
	spin_unlock_irq(&connection->resource->req_lock);

	list_for_each_entry_safe(peer_req, t, &reclaimed, w.list)
		drbd_free_net_peer_req(peer_req);

	/* possible callbacks here:
	 * e_end_block, and e_end_resync_block, e_send_discard_write.
	 * all ignore the last argument.
	 */
	list_for_each_entry_safe(peer_req, t, &work_list, w.list) {
		int err2;

		++n;
		/* list_del not necessary, next/prev members not touched */
		err2 = peer_req->w.cb(&peer_req->w, !!err);
		if (!err)
			err = err2;
		if (!list_empty(&peer_req->recv_order)) {
			drbd_free_page_chain(&connection->transport, &peer_req->page_chain, 0);
		} else
			drbd_free_peer_req(peer_req);
	}
	if (atomic_sub_and_test(n, &connection->done_ee_cnt))
		wake_up(&connection->ee_wait);

	return err;
}

static int drbd_recv(struct drbd_connection *connection, void **buf, size_t size, int flags)
{
	struct drbd_transport_ops *tr_ops = connection->transport.ops;
	int rv;

	rv = tr_ops->recv(&connection->transport, DATA_STREAM, buf, size, flags);

	if (rv < 0) {
		if (rv == -ECONNRESET)
			drbd_info(connection, "sock was reset by peer\n");
		else if (rv != -ERESTARTSYS)
			drbd_info(connection, "sock_recvmsg returned %d\n", rv);
	} else if (rv == 0) {
		if (test_bit(DISCONNECT_EXPECTED, &connection->flags)) {
			long t;
			rcu_read_lock();
			t = rcu_dereference(connection->transport.net_conf)->ping_timeo * HZ/10;
			rcu_read_unlock();

			t = wait_event_timeout(connection->resource->state_wait,
					       connection->cstate[NOW] < C_CONNECTED, t);

			if (t)
				goto out;
		}
		drbd_info(connection, "sock was shut down by peer\n");
	}

	if (rv != size)
		change_cstate(connection, C_BROKEN_PIPE, CS_HARD);

out:
	return rv;
}

static int drbd_recv_into(struct drbd_connection *connection, void *buf, size_t size)
{
	int err;

	err = drbd_recv(connection, &buf, size, CALLER_BUFFER);

	if (err != size) {
		if (err >= 0)
			err = -EIO;
	} else
		err = 0;
	return err;
}

static int drbd_recv_all(struct drbd_connection *connection, void **buf, size_t size)
{
	int err;

	err = drbd_recv(connection, buf, size, 0);

	if (err != size) {
		if (err >= 0)
			err = -EIO;
	} else
		err = 0;
	return err;
}

static int drbd_recv_all_warn(struct drbd_connection *connection, void **buf, size_t size)
{
	int err;

	err = drbd_recv_all(connection, buf, size);
	if (err && !signal_pending(current))
		drbd_warn(connection, "short read (expected size %d)\n", (int)size);
	return err;
}

static int drbd_send_disconnect(struct drbd_connection *connection)
{
	if (connection->agreed_pro_version < 118)
		return 0;

	if (!conn_prepare_command(connection, 0, DATA_STREAM))
		return -EIO;
	return send_command(connection, -1, P_DISCONNECT, DATA_STREAM);
}

/* Gets called if a connection is established, or if a new minor gets created
   in a connection */
int drbd_connected(struct drbd_peer_device *peer_device)
{
	struct drbd_device *device = peer_device->device;
	u64 weak_nodes = 0;
	int err;

	atomic_set(&peer_device->packet_seq, 0);
	peer_device->peer_seq = 0;

	if (device->resource->role[NOW] == R_PRIMARY)
		weak_nodes = drbd_weak_nodes_device(device);

	err = drbd_send_sync_param(peer_device);
	if (!err)
		err = drbd_send_sizes(peer_device, 0, 0);
	if (!err)
		err = drbd_send_uuids(peer_device, 0, weak_nodes);
	if (!err) {
		set_bit(INITIAL_STATE_SENT, &peer_device->flags);
		err = drbd_send_current_state(peer_device);
	}

	clear_bit(USE_DEGR_WFC_T, &peer_device->flags);
	clear_bit(RESIZE_PENDING, &peer_device->flags);
	mod_timer(&device->request_timer, jiffies + HZ); /* just start it here. */
	return err;
}

void conn_connect2(struct drbd_connection *connection)
{
	struct drbd_peer_device *peer_device;
	int vnr;

	rcu_read_lock();
	idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
		struct drbd_device *device = peer_device->device;
		kref_get(&device->kref);
		/* connection cannot go away: caller holds a reference. */
		rcu_read_unlock();

		down_read_non_owner(&device->uuid_sem);
		set_bit(HOLDING_UUID_READ_LOCK, &peer_device->flags);
		/* since drbd_connected() is also called from drbd_create_device()
		   aquire lock here before calling drbd_connected(). */
		drbd_connected(peer_device);

		rcu_read_lock();
		kref_put(&device->kref, drbd_destroy_device);
	}
	rcu_read_unlock();
	drbd_uncork(connection, DATA_STREAM);
}

static bool initial_states_received(struct drbd_connection *connection)
{
	struct drbd_peer_device *peer_device;
	int vnr;
	bool rv = true;

	rcu_read_lock();
	idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
		if (!test_bit(INITIAL_STATE_RECEIVED, &peer_device->flags)) {
			rv = false;
			break;
		}
	}
	rcu_read_unlock();

	return rv;
}

void wait_initial_states_received(struct drbd_connection *connection)
{
	struct net_conf *nc;
	long timeout;

	rcu_read_lock();
	nc = rcu_dereference(connection->transport.net_conf);
	timeout = nc->ping_timeo * 4 * HZ/10;
	rcu_read_unlock();
	wait_event_interruptible_timeout(connection->ee_wait,
					 initial_states_received(connection),
					 timeout);
}

void connect_timer_fn(struct timer_list *t)
{
	struct drbd_connection *connection = from_timer(connection, t, connect_timer);
	struct drbd_resource *resource = connection->resource;
	unsigned long irq_flags;

	spin_lock_irqsave(&resource->req_lock, irq_flags);
	drbd_queue_work(&connection->sender_work, &connection->connect_timer_work);
	spin_unlock_irqrestore(&resource->req_lock, irq_flags);
}

static void arm_connect_timer(struct drbd_connection *connection, unsigned long expires)
{
	bool was_pending = mod_timer(&connection->connect_timer, expires);

	if (was_pending) {
		kref_debug_put(&connection->kref_debug, 11);
		kref_put(&connection->kref, drbd_destroy_connection);
	}
}

static bool retry_by_rr_conflict(struct drbd_connection *connection)
{
	enum drbd_after_sb_p rr_conflict;
	struct net_conf *nc;

	rcu_read_lock();
	nc = rcu_dereference(connection->transport.net_conf);
	rr_conflict = nc->rr_conflict;
	rcu_read_unlock();

	return rr_conflict == ASB_RETRY_CONNECT;
}

static int connect_work(struct drbd_work *work, int cancel)
{
	struct drbd_connection *connection =
		container_of(work, struct drbd_connection, connect_timer_work);
	struct drbd_resource *resource = connection->resource;
	enum drbd_state_rv rv;
	long t = resource->res_opts.auto_promote_timeout * HZ / 10;
	bool retry = retry_by_rr_conflict(connection);
	bool incompat_states;

	if (connection->cstate[NOW] != C_CONNECTING)
		goto out_put;

	if (connection->agreed_pro_version == 117)
		wait_initial_states_received(connection);

	do {
		/* Carefully check if it is okay to do a two_phase_commit from sender context */
		if (down_trylock(&resource->state_sem)) {
			rv = SS_CONCURRENT_ST_CHG;
			break;
		}
		rv = change_cstate(connection, C_CONNECTED, CS_SERIALIZE |
				   CS_ALREADY_SERIALIZED | CS_VERBOSE | CS_DONT_RETRY);
		up(&resource->state_sem);
		if (rv != SS_PRIMARY_READER)
			break;

		/* We have a connection established, peer is primary. On my side is a
		   read-only opener, probably udev or some other scanning after device creating.
		   This short lived read-only open prevents now that we can continue.
		   Better retry after the read-only opener goes away. */

		t = wait_event_interruptible_timeout(resource->state_wait,
						     !drbd_open_ro_count(resource),
						     t);
	} while (t > 0);

	incompat_states = (rv == SS_CW_FAILED_BY_PEER || rv == SS_TWO_PRIMARIES);

	if (rv >= SS_SUCCESS) {
		if (connection->agreed_pro_version < 117)
			conn_connect2(connection);
	} else if (rv == SS_TIMEOUT || rv == SS_CONCURRENT_ST_CHG) {
		if (connection->cstate[NOW] != C_CONNECTING)
			goto out_put;
		arm_connect_timer(connection, jiffies + HZ/20);
		return 0; /* Return early. Keep the reference on the connection! */
	} else if (rv == SS_HANDSHAKE_RETRY || (incompat_states && retry)) {
		arm_connect_timer(connection, jiffies + HZ);
		return 0; /* Keep reference */
	} else if (rv == SS_HANDSHAKE_DISCONNECT || (incompat_states && !retry)) {
		drbd_send_disconnect(connection);
		change_cstate(connection, C_DISCONNECTING, CS_HARD);
	} else {
		drbd_info(connection, "Failure to connect %d %s; retrying\n",
			  rv, drbd_set_st_err_str(rv));
		change_cstate(connection, C_NETWORK_FAILURE, CS_HARD);
	}

 out_put:
	kref_debug_put(&connection->kref_debug, 11);
	kref_put(&connection->kref, drbd_destroy_connection);
	return 0;
}

/*
 * Returns true if we have a valid connection.
 */
static bool conn_connect(struct drbd_connection *connection)
{
	struct drbd_transport *transport = &connection->transport;
	struct drbd_resource *resource = connection->resource;
	int ping_timeo, ping_int, h, err, vnr, timeout;
	struct drbd_peer_device *peer_device;
	struct net_conf *nc;
	bool discard_my_data;
	bool have_mutex;
	bool no_addr = false;

start:
	have_mutex = false;
	clear_bit(DISCONNECT_EXPECTED, &connection->flags);
	if (change_cstate(connection, C_CONNECTING, CS_VERBOSE) < SS_SUCCESS) {
		/* We do not have a network config. */
		return false;
	}

	/* Assume that the peer only understands our minimum supported
	 * protocol version; until we know better. */
	connection->agreed_pro_version = drbd_protocol_version_min;

	err = transport->ops->connect(transport);
	if (err == -EAGAIN) {
		enum drbd_conn_state cstate;
		spin_lock_irq(&resource->req_lock); /* See commit message */
		cstate = connection->cstate[NOW];
		spin_unlock_irq(&resource->req_lock);
		if (cstate == C_DISCONNECTING)
			return false;
		goto retry;
	} else if (err == -EADDRNOTAVAIL) {
		struct net_conf *nc;
		int connect_int;
		long t;

		rcu_read_lock();
		nc = rcu_dereference(transport->net_conf);
		connect_int = nc ? nc->connect_int : 10;
		rcu_read_unlock();

		if (!no_addr) {
			drbd_warn(connection,
				  "Configured local address not found, retrying every %d sec, "
				  "err=%d\n", connect_int, err);
			no_addr = true;
		}

		t = schedule_timeout_interruptible(connect_int * HZ);
		if (t || connection->cstate[NOW] == C_DISCONNECTING)
			return false;
		goto start;
	} else if (err < 0) {
		drbd_warn(connection, "Failed to initiate connection, err=%d\n", err);
		goto abort;
	}

	connection->last_received = jiffies;

	rcu_read_lock();
	nc = rcu_dereference(connection->transport.net_conf);
	ping_timeo = nc->ping_timeo;
	ping_int = nc->ping_int;
	rcu_read_unlock();

	/* Make sure we are "uncorked", otherwise we risk timeouts,
	 * in case this is a reconnect and we had been corked before. */
	drbd_uncork(connection, CONTROL_STREAM);
	drbd_uncork(connection, DATA_STREAM);

	/* Make sure the handshake happens without interference from other threads,
	 * or the challenge response authentication could be garbled. */
	mutex_lock(&connection->mutex[DATA_STREAM]);
	have_mutex = true;
	transport->ops->set_rcvtimeo(transport, DATA_STREAM, ping_timeo * 4 * HZ/10);
	transport->ops->set_rcvtimeo(transport, CONTROL_STREAM, ping_int * HZ);

	h = drbd_do_features(connection);
	if (h < 0)
		goto abort;
	if (h == 0)
		goto retry;

	if (connection->cram_hmac_tfm) {
		switch (drbd_do_auth(connection)) {
		case -1:
			drbd_err(connection, "Authentication of peer failed\n");
			goto abort;
		case 0:
			drbd_err(connection, "Authentication of peer failed, trying again.\n");
			goto retry;
		}
	}

	discard_my_data = test_bit(CONN_DISCARD_MY_DATA, &connection->flags);

	if (__drbd_send_protocol(connection, P_PROTOCOL) == -EOPNOTSUPP)
		goto abort;

	rcu_read_lock();
	idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
		if (discard_my_data)
			set_bit(DISCARD_MY_DATA, &peer_device->flags);
		else
			clear_bit(DISCARD_MY_DATA, &peer_device->flags);
	}
	rcu_read_unlock();
	mutex_unlock(&connection->mutex[DATA_STREAM]);
	have_mutex = false;

	drbd_thread_start(&connection->ack_receiver);
	connection->ack_sender =
		alloc_ordered_workqueue("drbd_as_%s", WQ_MEM_RECLAIM, connection->resource->name);
	if (!connection->ack_sender) {
		drbd_err(connection, "Failed to create workqueue ack_sender\n");
		schedule_timeout_uninterruptible(HZ);
		goto retry;
	}

	atomic_set(&connection->ap_in_flight, 0);
	atomic_set(&connection->rs_in_flight, 0);

	if (connection->agreed_pro_version >= 110) {
		/* Allow 5 seconds for the two-phase commits */
		transport->ops->set_rcvtimeo(transport, DATA_STREAM, ping_timeo * 10 * HZ);

		if (connection->agreed_pro_version == 117)
			conn_connect2(connection);

		if (resource->res_opts.node_id < connection->peer_node_id) {
			kref_get(&connection->kref);
			kref_debug_get(&connection->kref_debug, 11);
			connection->connect_timer_work.cb = connect_work;
			timeout = twopc_retry_timeout(resource, 0);
			drbd_debug(connection, "Waiting for %ums to avoid transaction "
				   "conflicts\n", jiffies_to_msecs(timeout));
			arm_connect_timer(connection, jiffies + timeout);
		}
	} else {
		enum drbd_state_rv rv;
		rv = change_cstate(connection, C_CONNECTED,
				   CS_VERBOSE | CS_WAIT_COMPLETE | CS_SERIALIZE | CS_LOCAL_ONLY);
		if (rv < SS_SUCCESS || connection->cstate[NOW] != C_CONNECTED)
			goto retry;
		conn_connect2(connection);
	}
	return true;

retry:
	if (have_mutex)
		mutex_unlock(&connection->mutex[DATA_STREAM]);
	conn_disconnect(connection);
	schedule_timeout_interruptible(HZ);
	goto start;

abort:
	if (have_mutex)
		mutex_unlock(&connection->mutex[DATA_STREAM]);
	change_cstate(connection, C_DISCONNECTING, CS_HARD);
	return false;
}

static int decode_header(struct drbd_connection *connection, void *header, struct packet_info *pi)
{
	unsigned int header_size = drbd_header_size(connection);

	if (header_size == sizeof(struct p_header100) &&
	    *(__be32 *)header == cpu_to_be32(DRBD_MAGIC_100)) {
		struct p_header100 *h = header;
		u16 vnr = be16_to_cpu(h->volume);

		if (h->pad != 0) {
			drbd_err(connection, "Header padding is not zero\n");
			return -EINVAL;
		}
		pi->vnr = vnr == ((u16) 0xFFFF) ? -1 : vnr;

		pi->cmd = be16_to_cpu(h->command);
		pi->size = be32_to_cpu(h->length);
	} else if (header_size == sizeof(struct p_header95) &&
		   *(__be16 *)header == cpu_to_be16(DRBD_MAGIC_BIG)) {
		struct p_header95 *h = header;
		pi->cmd = be16_to_cpu(h->command);
		pi->size = be32_to_cpu(h->length);
		pi->vnr = 0;
	} else if (header_size == sizeof(struct p_header80) &&
		   *(__be32 *)header == cpu_to_be32(DRBD_MAGIC)) {
		struct p_header80 *h = header;
		pi->cmd = be16_to_cpu(h->command);
		pi->size = be16_to_cpu(h->length);
		pi->vnr = 0;
	} else {
		drbd_err(connection, "Wrong magic value 0x%08x in protocol version %d\n",
			 be32_to_cpu(*(__be32 *)header),
			 connection->agreed_pro_version);
		return -EINVAL;
	}
	pi->data = header + header_size;
	return 0;
}

static void drbd_unplug_all_devices(struct drbd_connection *connection)
{
	if (current->plug == &connection->receiver_plug) {
		blk_finish_plug(&connection->receiver_plug);
		blk_start_plug(&connection->receiver_plug);
	} /* else: maybe just schedule() ?? */
}

static int drbd_recv_header(struct drbd_connection *connection, struct packet_info *pi)
{
	void *buffer;
	int err;

	err = drbd_recv_all_warn(connection, &buffer, drbd_header_size(connection));
	if (err)
		return err;

	err = decode_header(connection, buffer, pi);
	connection->last_received = jiffies;

	return err;
}

static int drbd_recv_header_maybe_unplug(struct drbd_connection *connection, struct packet_info *pi)
{
	struct drbd_transport_ops *tr_ops = connection->transport.ops;
	unsigned int size = drbd_header_size(connection);
	void *buffer;
	int err;

	err = tr_ops->recv(&connection->transport, DATA_STREAM, &buffer,
			   size, MSG_NOSIGNAL | MSG_DONTWAIT);
	if (err != size) {
		int rflags = 0;

		/* If we have nothing in the receive buffer now, to reduce
		 * application latency, try to drain the backend queues as
		 * quickly as possible, and let remote TCP know what we have
		 * received so far. */
		if (err == -EAGAIN) {
			tr_ops->hint(&connection->transport, DATA_STREAM, QUICKACK);
			drbd_unplug_all_devices(connection);
		} else if (err > 0) {
			size -= err;
			rflags |= GROW_BUFFER;
		}

		err = drbd_recv(connection, &buffer, size, rflags);
		if (err != size) {
			if (err >= 0)
				err = -EIO;
		} else
			err = 0;

		if (err)
			return err;
	}

	err = decode_header(connection, buffer, pi);
	connection->last_received = jiffies;

	return err;
}

/* This is blkdev_issue_flush, but asynchronous.
 * We want to submit to all component volumes in parallel,
 * then wait for all completions.
 */
struct issue_flush_context {
	atomic_t pending;
	int error;
	struct completion done;
};
struct one_flush_context {
	struct drbd_device *device;
	struct issue_flush_context *ctx;
};

static void one_flush_endio(struct bio *bio)
{
	struct one_flush_context *octx = bio->bi_private;
	struct drbd_device *device = octx->device;
	struct issue_flush_context *ctx = octx->ctx;

	blk_status_t status = bio->bi_status;

	if (status) {
		ctx->error = blk_status_to_errno(status);
		drbd_info(device, "local disk FLUSH FAILED with status %d\n", status);
	}
	kfree(octx);
	bio_put(bio);

	clear_bit(FLUSH_PENDING, &device->flags);
	put_ldev(device);
	kref_debug_put(&device->kref_debug, 7);
	kref_put(&device->kref, drbd_destroy_device);

	if (atomic_dec_and_test(&ctx->pending))
		complete(&ctx->done);
}

static void submit_one_flush(struct drbd_device *device, struct issue_flush_context *ctx)
{
	struct bio *bio = bio_alloc(GFP_NOIO, 0);
	struct one_flush_context *octx = kmalloc(sizeof(*octx), GFP_NOIO);
	if (!bio || !octx) {
		drbd_warn(device, "Could not allocate a bio, CANNOT ISSUE FLUSH\n");
		/* FIXME: what else can I do now?  disconnecting or detaching
		 * really does not help to improve the state of the world, either.
		 */
		kfree(octx);
		if (bio)
			bio_put(bio);

		ctx->error = -ENOMEM;
		put_ldev(device);
		kref_debug_put(&device->kref_debug, 7);
		kref_put(&device->kref, drbd_destroy_device);
		return;
	}

	octx->device = device;
	octx->ctx = ctx;
	bio_set_dev(bio, device->ldev->backing_bdev);
	bio->bi_private = octx;
	bio->bi_end_io = one_flush_endio;

	device->flush_jif = jiffies;
	set_bit(FLUSH_PENDING, &device->flags);
	atomic_inc(&ctx->pending);
	bio->bi_opf = REQ_OP_FLUSH | REQ_PREFLUSH;
	submit_bio(bio);
}

static enum finish_epoch drbd_flush_after_epoch(struct drbd_connection *connection, struct drbd_epoch *epoch)
{
	struct drbd_resource *resource = connection->resource;

	if (resource->write_ordering >= WO_BDEV_FLUSH) {
		struct drbd_device *device;
		struct issue_flush_context ctx;
		int vnr;

		atomic_set(&ctx.pending, 1);
		ctx.error = 0;
		init_completion(&ctx.done);

		rcu_read_lock();
		idr_for_each_entry(&resource->devices, device, vnr) {
			if (!get_ldev(device))
				continue;
			kref_get(&device->kref);
			kref_debug_get(&device->kref_debug, 7);
			rcu_read_unlock();

			submit_one_flush(device, &ctx);

			rcu_read_lock();
		}
		rcu_read_unlock();

		/* Do we want to add a timeout,
		 * if disk-timeout is set? */
		if (!atomic_dec_and_test(&ctx.pending))
			wait_for_completion(&ctx.done);

		if (ctx.error) {
			/* would rather check on EOPNOTSUPP, but that is not reliable.
			 * don't try again for ANY return value != 0
			 * if (rv == -EOPNOTSUPP) */
			/* Any error is already reported by bio_endio callback. */
			drbd_bump_write_ordering(connection->resource, NULL, WO_DRAIN_IO);
		}
	}

	/* If called before sending P_CONFIRM_STABLE, we don't have the epoch
	 * (and must not finish it yet, anyways) */
	if (epoch == NULL)
		return FE_STILL_LIVE;
	return drbd_may_finish_epoch(connection, epoch, EV_BARRIER_DONE);
}

static int w_flush(struct drbd_work *w, int cancel)
{
	struct flush_work *fw = container_of(w, struct flush_work, w);
	struct drbd_epoch *epoch = fw->epoch;
	struct drbd_connection *connection = epoch->connection;

	kfree(fw);

	if (!test_and_set_bit(DE_BARRIER_IN_NEXT_EPOCH_ISSUED, &epoch->flags))
		drbd_flush_after_epoch(connection, epoch);

	drbd_may_finish_epoch(connection, epoch, EV_PUT |
			      (connection->cstate[NOW] < C_CONNECTED ? EV_CLEANUP : 0));

	return 0;
}

static void drbd_send_b_ack(struct drbd_connection *connection, u32 barrier_nr, u32 set_size)
{
	struct p_barrier_ack *p;

	if (connection->cstate[NOW] < C_CONNECTED)
		return;

	p = conn_prepare_command(connection, sizeof(*p), CONTROL_STREAM);
	if (!p)
		return;
	p->barrier = barrier_nr;
	p->set_size = cpu_to_be32(set_size);
	send_command(connection, -1, P_BARRIER_ACK, CONTROL_STREAM);
}

static void drbd_send_confirm_stable(struct drbd_peer_request *peer_req)
{
	struct drbd_connection *connection = peer_req->peer_device->connection;
	struct drbd_resource *resource = connection->resource;
	struct drbd_epoch *epoch = peer_req->epoch;
	struct drbd_peer_request *oldest, *youngest;
	struct p_confirm_stable *p;
	int count;

	if (connection->cstate[NOW] < C_CONNECTED)
		return;

	/* peer_req is not on stable storage yet, but the only one in this epoch.
	 * Nothing to confirm, just wait for the normal barrier_ack and peer_ack
	 * to do their work. */
	oldest = epoch->oldest_unconfirmed_peer_req;
	if (oldest == peer_req)
		return;

	p = conn_prepare_command(connection, sizeof(*p), CONTROL_STREAM);
	if (!p)
		return;

	/* receive_Data() does a list_add_tail() for every requests, which
	 * means the oldest is .next, the currently blocked one that triggered
	 * this code path is .prev, and the youngest that now should be on
	 * stable storage is .prev->prev */
	spin_lock_irq(&resource->req_lock);
	youngest = list_entry(peer_req->recv_order.prev, struct drbd_peer_request, recv_order);
	spin_unlock_irq(&resource->req_lock);

	count = atomic_read(&epoch->epoch_size) - atomic_read(&epoch->confirmed) - 1;
	atomic_add(count, &epoch->confirmed);
	epoch->oldest_unconfirmed_peer_req = peer_req;

	D_ASSERT(connection, oldest->epoch == youngest->epoch);
	D_ASSERT(connection, count > 0);

	p->oldest_block_id = oldest->block_id;
	p->youngest_block_id = youngest->block_id;
	p->set_size = cpu_to_be32(count);
	p->pad = 0;

	send_command(connection, -1, P_CONFIRM_STABLE, CONTROL_STREAM);
}

/**
 * drbd_may_finish_epoch() - Applies an epoch_event to the epoch's state, eventually finishes it.
 * @connection:	DRBD connection.
 * @epoch:	Epoch object.
 * @ev:		Epoch event.
 */
static enum finish_epoch drbd_may_finish_epoch(struct drbd_connection *connection,
					       struct drbd_epoch *epoch,
					       enum epoch_event ev)
{
	int finish, epoch_size;
	struct drbd_epoch *next_epoch;
	int schedule_flush = 0;
	enum finish_epoch rv = FE_STILL_LIVE;
	struct drbd_resource *resource = connection->resource;

	spin_lock(&connection->epoch_lock);
	do {
		next_epoch = NULL;
		finish = 0;

		epoch_size = atomic_read(&epoch->epoch_size);

		switch (ev & ~EV_CLEANUP) {
		case EV_PUT:
			atomic_dec(&epoch->active);
			break;
		case EV_GOT_BARRIER_NR:
			set_bit(DE_HAVE_BARRIER_NUMBER, &epoch->flags);

			/* Special case: If we just switched from WO_BIO_BARRIER to
			   WO_BDEV_FLUSH we should not finish the current epoch */
			if (test_bit(DE_CONTAINS_A_BARRIER, &epoch->flags) && epoch_size == 1 &&
			    resource->write_ordering != WO_BIO_BARRIER &&
			    epoch == connection->current_epoch)
				clear_bit(DE_CONTAINS_A_BARRIER, &epoch->flags);
			break;
		case EV_BARRIER_DONE:
			set_bit(DE_BARRIER_IN_NEXT_EPOCH_DONE, &epoch->flags);
			break;
		case EV_BECAME_LAST:
			/* nothing to do*/
			break;
		}

		if (epoch_size != 0 &&
		    atomic_read(&epoch->active) == 0 &&
		    (test_bit(DE_HAVE_BARRIER_NUMBER, &epoch->flags) || ev & EV_CLEANUP) &&
		    epoch->list.prev == &connection->current_epoch->list &&
		    !test_bit(DE_IS_FINISHING, &epoch->flags)) {
			/* Nearly all conditions are met to finish that epoch... */
			if (test_bit(DE_BARRIER_IN_NEXT_EPOCH_DONE, &epoch->flags) ||
			    resource->write_ordering == WO_NONE ||
			    (epoch_size == 1 && test_bit(DE_CONTAINS_A_BARRIER, &epoch->flags)) ||
			    ev & EV_CLEANUP) {
				finish = 1;
				set_bit(DE_IS_FINISHING, &epoch->flags);
			} else if (!test_bit(DE_BARRIER_IN_NEXT_EPOCH_ISSUED, &epoch->flags) &&
				 resource->write_ordering == WO_BIO_BARRIER) {
				atomic_inc(&epoch->active);
				schedule_flush = 1;
			}
		}
		if (finish) {
			if (!(ev & EV_CLEANUP)) {
				/* adjust for nr requests already confirmed via P_CONFIRM_STABLE, if any. */
				epoch_size -= atomic_read(&epoch->confirmed);
				spin_unlock(&connection->epoch_lock);
				drbd_send_b_ack(epoch->connection, epoch->barrier_nr, epoch_size);
				spin_lock(&connection->epoch_lock);
			}

			if (connection->current_epoch != epoch) {
				next_epoch = list_entry(epoch->list.next, struct drbd_epoch, list);
				list_del(&epoch->list);
				ev = EV_BECAME_LAST | (ev & EV_CLEANUP);
				connection->epochs--;
				kfree(epoch);

				if (rv == FE_STILL_LIVE)
					rv = FE_DESTROYED;
			} else {
				epoch->oldest_unconfirmed_peer_req = NULL;
				epoch->flags = 0;
				atomic_set(&epoch->epoch_size, 0);
				atomic_set(&epoch->confirmed, 0);
				/* atomic_set(&epoch->active, 0); is alrady zero */
				if (rv == FE_STILL_LIVE)
					rv = FE_RECYCLED;
			}
		}

		if (!next_epoch)
			break;

		epoch = next_epoch;
	} while (1);

	spin_unlock(&connection->epoch_lock);

	if (schedule_flush) {
		struct flush_work *fw;
		fw = kmalloc(sizeof(*fw), GFP_ATOMIC);
		if (fw) {
			fw->w.cb = w_flush;
			fw->epoch = epoch;
			drbd_queue_work(&resource->work, &fw->w);
		} else {
			drbd_warn(resource, "Could not kmalloc a flush_work obj\n");
			set_bit(DE_BARRIER_IN_NEXT_EPOCH_ISSUED, &epoch->flags);
			/* That is not a recursion, only one level */
			drbd_may_finish_epoch(connection, epoch, EV_BARRIER_DONE);
			drbd_may_finish_epoch(connection, epoch, EV_PUT);
		}
	}

	return rv;
}

static enum write_ordering_e
max_allowed_wo(struct drbd_backing_dev *bdev, enum write_ordering_e wo)
{
	struct disk_conf *dc;

	dc = rcu_dereference(bdev->disk_conf);

	if (wo == WO_BIO_BARRIER && !dc->disk_barrier)
		wo = WO_BDEV_FLUSH;
	if (wo == WO_BDEV_FLUSH && !dc->disk_flushes)
		wo = WO_DRAIN_IO;
	if (wo == WO_DRAIN_IO && !dc->disk_drain)
		wo = WO_NONE;

	return wo;
}

/**
 * drbd_bump_write_ordering() - Fall back to an other write ordering method
 * @resource:	DRBD resource.
 * @wo:		Write ordering method to try.
 */
void drbd_bump_write_ordering(struct drbd_resource *resource, struct drbd_backing_dev *bdev,
			      enum write_ordering_e wo) __must_hold(local)
{
	struct drbd_device *device;
	enum write_ordering_e pwo;
	int vnr, i = 0;
	static char *write_ordering_str[] = {
		[WO_NONE] = "none",
		[WO_DRAIN_IO] = "drain",
		[WO_BDEV_FLUSH] = "flush",
		[WO_BIO_BARRIER] = "barrier",
	};

	pwo = resource->write_ordering;
	if (wo != WO_BIO_BARRIER)
		wo = min(pwo, wo);
	rcu_read_lock();
	idr_for_each_entry(&resource->devices, device, vnr) {
		if (i++ == 1 && wo == WO_BIO_BARRIER)
			wo = WO_BDEV_FLUSH; /* WO = barrier does not handle multiple volumes */

		if (get_ldev(device)) {
			wo = max_allowed_wo(device->ldev, wo);
			if (device->ldev == bdev)
				bdev = NULL;
			put_ldev(device);
		}
	}

	if (bdev)
		wo = max_allowed_wo(bdev, wo);

	rcu_read_unlock();

	resource->write_ordering = wo;
	if (pwo != resource->write_ordering || wo == WO_BIO_BARRIER)
		drbd_info(resource, "Method to ensure write ordering: %s\n", write_ordering_str[resource->write_ordering]);
}

/*
 * We *may* ignore the discard-zeroes-data setting, if so configured.
 *
 * Assumption is that this "discard_zeroes_data=0" is only because the backend
 * may ignore partial unaligned discards.
 *
 * LVM/DM thin as of at least
 *   LVM version:     2.02.115(2)-RHEL7 (2015-01-28)
 *   Library version: 1.02.93-RHEL7 (2015-01-28)
 *   Driver version:  4.29.0
 * still behaves this way.
 *
 * For unaligned (wrt. alignment and granularity) or too small discards,
 * we zero-out the initial (and/or) trailing unaligned partial chunks,
 * but discard all the aligned full chunks.
 *
 * At least for LVM/DM thin, with skip_block_zeroing=false,
 * the result is effectively "discard_zeroes_data=1".
 */
/* flags: EE_TRIM|EE_ZEROOUT */
int drbd_issue_discard_or_zero_out(struct drbd_device *device, sector_t start, unsigned int nr_sectors, int flags)
{
	struct block_device *bdev = device->ldev->backing_bdev;
	struct request_queue *q = bdev_get_queue(bdev);
	sector_t tmp, nr;
	unsigned int max_discard_sectors, granularity;
	int alignment;
	int err = 0;

	if ((flags & EE_ZEROOUT) || !(flags & EE_TRIM))
		goto zero_out;

	/* Zero-sector (unknown) and one-sector granularities are the same.  */
	granularity = max(q->limits.discard_granularity >> 9, 1U);
	alignment = (bdev_discard_alignment(bdev) >> 9) % granularity;

	max_discard_sectors = min(q->limits.max_discard_sectors, (1U << 22));
	max_discard_sectors -= max_discard_sectors % granularity;
	if (unlikely(!max_discard_sectors))
		goto zero_out;

	if (nr_sectors < granularity)
		goto zero_out;

	tmp = start;
	if (sector_div(tmp, granularity) != alignment) {
		if (nr_sectors < 2*granularity)
			goto zero_out;
		/* start + gran - (start + gran - align) % gran */
		tmp = start + granularity - alignment;
		tmp = start + granularity - sector_div(tmp, granularity);

		nr = tmp - start;
		/* don't flag BLKDEV_ZERO_NOUNMAP, we don't know how many
		 * layers are below us, some may have smaller granularity */
		err |= blkdev_issue_zeroout(bdev, start, nr, GFP_NOIO, 0);
		nr_sectors -= nr;
		start = tmp;
	}
	while (nr_sectors >= max_discard_sectors) {
		err |= blkdev_issue_discard(bdev, start, max_discard_sectors, GFP_NOIO, 0);
		nr_sectors -= max_discard_sectors;
		start += max_discard_sectors;
	}
	if (nr_sectors) {
		/* max_discard_sectors is unsigned int (and a multiple of
		 * granularity, we made sure of that above already);
		 * nr is < max_discard_sectors;
		 * I don't need sector_div here, even though nr is sector_t */
		nr = nr_sectors;
		nr -= (unsigned int)nr % granularity;
		if (nr) {
			err |= blkdev_issue_discard(bdev, start, nr, GFP_NOIO, 0);
			nr_sectors -= nr;
			start += nr;
		}
	}
 zero_out:
	if (nr_sectors) {
		err |= blkdev_issue_zeroout(bdev, start, nr_sectors, GFP_NOIO,
				(flags & EE_TRIM) ? 0 : BLKDEV_ZERO_NOUNMAP);
	}
	return err != 0;
}

static bool can_do_reliable_discards(struct drbd_device *device)
{
	struct request_queue *q = bdev_get_queue(device->ldev->backing_bdev);
	struct disk_conf *dc;
	bool can_do;

	if (!blk_queue_discard(q))
		return false;

	if (queue_discard_zeroes_data(q))
		return true;

	rcu_read_lock();
	dc = rcu_dereference(device->ldev->disk_conf);
	can_do = dc->discard_zeroes_if_aligned;
	rcu_read_unlock();
	return can_do;
}

static void drbd_issue_peer_discard_or_zero_out(struct drbd_device *device, struct drbd_peer_request *peer_req)
{
	/* If the backend cannot discard, or does not guarantee
	 * read-back zeroes in discarded ranges, we fall back to
	 * zero-out.  Unless configuration specifically requested
	 * otherwise. */
	if (!can_do_reliable_discards(device))
		peer_req->flags |= EE_ZEROOUT;

	if (drbd_issue_discard_or_zero_out(device, peer_req->i.sector,
	    peer_req->i.size >> 9, peer_req->flags & (EE_ZEROOUT|EE_TRIM)))
		peer_req->flags |= EE_WAS_ERROR;
	drbd_endio_write_sec_final(peer_req);
}

static void drbd_issue_peer_wsame(struct drbd_device *device,
				  struct drbd_peer_request *peer_req)
{
	struct block_device *bdev = device->ldev->backing_bdev;
	sector_t s = peer_req->i.sector;
	sector_t nr = peer_req->i.size >> 9;
	if (blkdev_issue_write_same(bdev, s, nr, GFP_NOIO, peer_req->page_chain.head))
		peer_req->flags |= EE_WAS_ERROR;
	drbd_endio_write_sec_final(peer_req);
}

static bool conn_wait_ee_cond(struct drbd_connection *connection, struct list_head *head)
{
	struct drbd_resource *resource = connection->resource;
	bool done;

	spin_lock_irq(&resource->req_lock);
	done = list_empty(head);
	spin_unlock_irq(&resource->req_lock);

	if (!done)
		drbd_unplug_all_devices(connection);

	return done;
}

static void conn_wait_ee_empty(struct drbd_connection *connection, struct list_head *head)
{
	wait_event(connection->ee_wait, conn_wait_ee_cond(connection, head));
}

static int peer_request_fault_type(struct drbd_peer_request *peer_req)
{
	if (peer_req_op(peer_req) == REQ_OP_READ) {
		return peer_req->flags & EE_APPLICATION ?
			DRBD_FAULT_DT_RD : DRBD_FAULT_RS_RD;
	} else {
		return peer_req->flags & EE_APPLICATION ?
			DRBD_FAULT_DT_WR : DRBD_FAULT_RS_WR;
	}
}

/**
 * drbd_submit_peer_request()
 * @peer_req:	peer request
 *
 * May spread the pages to multiple bios,
 * depending on bio_add_page restrictions.
 *
 * Returns 0 if all bios have been submitted,
 * -ENOMEM if we could not allocate enough bios,
 * -ENOSPC (any better suggestion?) if we have not been able to bio_add_page a
 *  single page to an empty bio (which should never happen and likely indicates
 *  that the lower level IO stack is in some way broken). This has been observed
 *  on certain Xen deployments.
 *
 *  When this function returns 0, it "consumes" an ldev reference; the
 *  reference is released when the request completes.
 */
/* TODO allocate from our own bio_set. */
int drbd_submit_peer_request(struct drbd_peer_request *peer_req)
{
	struct drbd_device *device = peer_req->peer_device->device;
	struct bio *bios = NULL;
	struct bio *bio;
	struct page *page = peer_req->page_chain.head;
	sector_t sector = peer_req->i.sector;
	unsigned data_size = peer_req->i.size;
	unsigned n_bios = 0;
	unsigned nr_pages = peer_req->page_chain.nr_pages;
	int err = -ENOMEM;

	if (peer_req->flags & EE_SET_OUT_OF_SYNC)
		drbd_set_out_of_sync(peer_req->peer_device,
				peer_req->i.sector, peer_req->i.size);

	/* TRIM/DISCARD: for now, always use the helper function
	 * blkdev_issue_zeroout(..., discard=true).
	 * It's synchronous, but it does the right thing wrt. bio splitting.
	 * Correctness first, performance later.  Next step is to code an
	 * asynchronous variant of the same.
	 */
	if (peer_req->flags & (EE_TRIM|EE_WRITE_SAME|EE_ZEROOUT)) {
		peer_req->submit_jif = jiffies;
		peer_req->flags |= EE_SUBMITTED;

		if (peer_req->flags & (EE_TRIM|EE_ZEROOUT))
			drbd_issue_peer_discard_or_zero_out(device, peer_req);
		else /* EE_WRITE_SAME */
			drbd_issue_peer_wsame(device, peer_req);
		return 0;
	}

	/* In most cases, we will only need one bio.  But in case the lower
	 * level restrictions happen to be different at this offset on this
	 * side than those of the sending peer, we may need to submit the
	 * request in more than one bio.
	 *
	 * Plain bio_alloc is good enough here, this is no DRBD internally
	 * generated bio, but a bio allocated on behalf of the peer.
	 */
next_bio:
	/* REQ_OP_WRITE_SAME, _DISCARD, _WRITE_ZEROES handled above.
	 * REQ_OP_FLUSH (empty flush) not expected,
	 * should have been mapped to a "drbd protocol barrier".
	 * REQ_OP_SECURE_ERASE: I don't see how we could ever support that.
	 */
	if (!(peer_req_op(peer_req) == REQ_OP_WRITE ||
				peer_req_op(peer_req) == REQ_OP_READ)) {
		drbd_err(device, "Invalid bio op received: 0x%x\n", peer_req->opf);
		err = -EINVAL;
		goto fail;
	}

	bio = bio_alloc(GFP_NOIO, nr_pages);
	if (!bio) {
		drbd_err(device, "submit_ee: Allocation of a bio failed (nr_pages=%u)\n", nr_pages);
		goto fail;
	}
	/* > peer_req->i.sector, unless this is the first bio */
	bio->bi_iter.bi_sector = sector;
	bio_set_dev(bio, device->ldev->backing_bdev);
	/* we special case some flags in the multi-bio case, see below
	 * (REQ_PREFLUSH, or BIO_RW_BARRIER in older kernels) */
	bio->bi_opf = peer_req->opf;
	bio->bi_private = peer_req;
	bio->bi_end_io = drbd_peer_request_endio;

	bio->bi_next = bios;
	bios = bio;
	++n_bios;

	page_chain_for_each(page) {
		unsigned off, len;
		int res;

		if (peer_req_op(peer_req) == REQ_OP_READ) {
			set_page_chain_offset(page, 0);
			set_page_chain_size(page, min_t(unsigned, data_size, PAGE_SIZE));
		}
		off = page_chain_offset(page);
		len = page_chain_size(page);

		if (off > PAGE_SIZE || len > PAGE_SIZE - off || len > data_size || len == 0) {
			drbd_err(device, "invalid page chain: offset %u size %u remaining data_size %u\n",
					off, len, data_size);
			err = -EINVAL;
			goto fail;
		}

		res = bio_add_page(bio, page, len, off);
		if (res <= 0) {
			/* A single page must always be possible!
			 * But in case it fails anyways,
			 * we deal with it, and complain (below). */
			if (bio->bi_vcnt == 0) {
				drbd_err(device,
					"bio_add_page(%p, %p, %u, %u): %d (bi_vcnt %u bi_max_vecs %u bi_sector %llu, bi_flags 0x%lx)\n",
					bio, page, len, off, res, bio->bi_vcnt, bio->bi_max_vecs, (uint64_t)bio->bi_iter.bi_sector,
					 (unsigned long)bio->bi_flags);
				err = -ENOSPC;
				goto fail;
			}
			goto next_bio;
		}
		data_size -= len;
		sector += len >> 9;
		--nr_pages;
	}
	D_ASSERT(device, data_size == 0);
	D_ASSERT(device, page == NULL);

	atomic_set(&peer_req->pending_bios, n_bios);
	/* for debugfs: update timestamp, mark as submitted */
	peer_req->submit_jif = jiffies;
	peer_req->flags |= EE_SUBMITTED;
	do {
		bio = bios;
		bios = bios->bi_next;
		bio->bi_next = NULL;

		drbd_submit_bio_noacct(device, peer_request_fault_type(peer_req), bio);

		/* strip off REQ_PREFLUSH,
		 * unless it is the first or last bio */
		if (bios && bios->bi_next)
			bios->bi_opf &= ~REQ_PREFLUSH;
	} while (bios);
	return 0;

fail:
	while (bios) {
		bio = bios;
		bios = bios->bi_next;
		bio_put(bio);
	}
	return err;
}

static void drbd_remove_peer_req_interval(struct drbd_device *device,
					  struct drbd_peer_request *peer_req)
{
	struct drbd_interval *i = &peer_req->i;

	drbd_remove_interval(&device->write_requests, i);
	drbd_clear_interval(i);
	peer_req->flags &= ~EE_IN_INTERVAL_TREE;

	/* Wake up any processes waiting for this peer request to complete.  */
	if (i->waiting)
		wake_up(&device->misc_wait);
}

/**
 * w_e_reissue() - Worker callback; Resubmit a bio
 * @device:	DRBD device.
 * @dw:		work object.
 * @cancel:	The connection will be closed anyways (unused in this callback)
 */
int w_e_reissue(struct drbd_work *w, int cancel) __releases(local)
{
	struct drbd_peer_request *peer_req =
		container_of(w, struct drbd_peer_request, w);
	struct drbd_peer_device *peer_device = peer_req->peer_device;
	struct drbd_device *device = peer_device->device;
	int err;
	/* We leave DE_CONTAINS_A_BARRIER and EE_IS_BARRIER in place,
	   (and DE_BARRIER_IN_NEXT_EPOCH_ISSUED in the previous Epoch)
	   so that we can finish that epoch in drbd_may_finish_epoch().
	   That is necessary if we already have a long chain of Epochs, before
	   we realize that BARRIER is actually not supported */

	/* As long as the -ENOTSUPP on the barrier is reported immediately
	   that will never trigger. If it is reported late, we will just
	   print that warning and continue correctly for all future requests
	   with WO_BDEV_FLUSH */
	if (previous_epoch(peer_device->connection, peer_req->epoch))
		drbd_warn(device, "Write ordering was not enforced (one time event)\n");

	/* we still have a local reference,
	 * get_ldev was done in receive_Data. */

	peer_req->w.cb = e_end_block;
	err = drbd_submit_peer_request(peer_req);
	switch (err) {
	case -ENOMEM:
		peer_req->w.cb = w_e_reissue;
		drbd_queue_work(&peer_device->connection->sender_work,
				&peer_req->w);
		/* retry later */
		fallthrough;
	case 0:
		/* keep worker happy and connection up */
		return 0;

	case -ENOSPC:
		/* no other error expected, but anyways: */
	default:
		/* forget the object,
		 * and cause a "Network failure" */
		spin_lock_irq(&device->resource->req_lock);
		list_del(&peer_req->w.list);
		drbd_remove_peer_req_interval(device, peer_req);
		spin_unlock_irq(&device->resource->req_lock);
		drbd_al_complete_io(device, &peer_req->i);
		drbd_may_finish_epoch(peer_device->connection, peer_req->epoch, EV_PUT | EV_CLEANUP);
		drbd_free_peer_req(peer_req);
		drbd_err(device, "submit failed, triggering re-connect\n");
		return err;
	}
}

static void conn_wait_done_ee_empty_or_disconnect(struct drbd_connection *connection)
{
	wait_event(connection->ee_wait,
		atomic_read(&connection->done_ee_cnt) == 0
		|| connection->cstate[NOW] < C_CONNECTED);
}

static void conn_wait_active_ee_empty_or_disconnect(struct drbd_connection *connection)
{
	if (atomic_read(&connection->active_ee_cnt) == 0)
		return;

	drbd_unplug_all_devices(connection);

	wait_event(connection->ee_wait,
		atomic_read(&connection->active_ee_cnt) == 0
		|| connection->cstate[NOW] < C_CONNECTED);
}

static int receive_Barrier(struct drbd_connection *connection, struct packet_info *pi)
{
	struct drbd_transport_ops *tr_ops = connection->transport.ops;
	int rv, issue_flush;
	struct p_barrier *p = pi->data;
	struct drbd_epoch *epoch;

	tr_ops->hint(&connection->transport, DATA_STREAM, QUICKACK);
	drbd_unplug_all_devices(connection);

	/* FIXME these are unacked on connection,
	 * not a specific (peer)device.
	 */
	connection->current_epoch->barrier_nr = p->barrier;
	connection->current_epoch->connection = connection;
	rv = drbd_may_finish_epoch(connection, connection->current_epoch, EV_GOT_BARRIER_NR);

	/* P_BARRIER_ACK may imply that the corresponding extent is dropped from
	 * the activity log, which means it would not be resynced in case the
	 * R_PRIMARY crashes now.
	 * Therefore we must send the barrier_ack after the barrier request was
	 * completed. */
	switch (connection->resource->write_ordering) {
	case WO_BIO_BARRIER:
	case WO_NONE:
		if (rv == FE_RECYCLED)
			return 0;
		break;

	case WO_BDEV_FLUSH:
	case WO_DRAIN_IO:
		if (rv == FE_STILL_LIVE) {
			set_bit(DE_BARRIER_IN_NEXT_EPOCH_ISSUED, &connection->current_epoch->flags);
			conn_wait_active_ee_empty_or_disconnect(connection);
			rv = drbd_flush_after_epoch(connection, connection->current_epoch);
		}
		if (rv == FE_RECYCLED)
			return 0;

		/* The ack_sender will send all the ACKs and barrier ACKs out, since
		   all EEs moved from the active_ee to the done_ee. We need to
		   provide a new epoch object for the EEs that come in soon */
		break;
	}

	/* receiver context, in the writeout path of the other node.
	 * avoid potential distributed deadlock */
	epoch = kzalloc(sizeof(struct drbd_epoch), GFP_NOIO);
	if (!epoch) {
		drbd_warn(connection, "Allocation of an epoch failed, slowing down\n");
		issue_flush = !test_and_set_bit(DE_BARRIER_IN_NEXT_EPOCH_ISSUED, &connection->current_epoch->flags);
		conn_wait_active_ee_empty_or_disconnect(connection);
		if (issue_flush) {
			rv = drbd_flush_after_epoch(connection, connection->current_epoch);
			if (rv == FE_RECYCLED)
				return 0;
		}

		conn_wait_done_ee_empty_or_disconnect(connection);

		return 0;
	}

	spin_lock(&connection->epoch_lock);
	if (atomic_read(&connection->current_epoch->epoch_size)) {
		list_add(&epoch->list, &connection->current_epoch->list);
		connection->current_epoch = epoch;
		connection->epochs++;
	} else {
		/* The current_epoch got recycled while we allocated this one... */
		kfree(epoch);
	}
	spin_unlock(&connection->epoch_lock);

	return 0;
}

/* pi->data points into some recv buffer, which may be
 * re-used/recycled/overwritten by the next receive operation.
 * (read_in_block via recv_resync_read) */
static void p_req_detail_from_pi(struct drbd_connection *connection,
		struct drbd_peer_request_details *d, struct packet_info *pi)
{
	struct p_trim *p = pi->data;
	bool is_trim_or_wsame = pi->cmd == P_TRIM || pi->cmd == P_WSAME || pi->cmd == P_ZEROES;
	unsigned int digest_size =
		pi->cmd != P_TRIM && connection->peer_integrity_tfm ?
		crypto_shash_digestsize(connection->peer_integrity_tfm) : 0;

	d->sector = be64_to_cpu(p->p_data.sector);
	d->block_id = p->p_data.block_id;
	d->peer_seq = be64_to_cpu(p->p_data.seq_num);
	d->dp_flags = be32_to_cpu(p->p_data.dp_flags);
	d->length = pi->size;
	d->bi_size = is_trim_or_wsame ? be32_to_cpu(p->size) : pi->size - digest_size;
	d->digest_size = digest_size;
}

/* used from receive_RSDataReply (recv_resync_read)
 * and from receive_Data.
 * data_size: actual payload ("data in")
 * 	for normal writes that is bi_size.
 * 	for discards, that is zero.
 * 	for write same, it is logical_block_size.
 * both trim and write same have the bi_size ("data len to be affected")
 * as extra argument in the packet header.
 */
static struct drbd_peer_request *
read_in_block(struct drbd_peer_device *peer_device, struct drbd_peer_request_details *d) __must_hold(local)
{
	struct drbd_device *device = peer_device->device;
	const uint64_t capacity = get_capacity(device->vdisk);
	struct drbd_peer_request *peer_req;
	int err;
	void *dig_in = peer_device->connection->int_dig_in;
	void *dig_vv = peer_device->connection->int_dig_vv;
	struct drbd_transport *transport = &peer_device->connection->transport;
	struct drbd_transport_ops *tr_ops = transport->ops;

	if (d->digest_size) {
		err = drbd_recv_into(peer_device->connection, dig_in, d->digest_size);
		if (err)
			return NULL;
	}

	if (!expect(peer_device, IS_ALIGNED(d->bi_size, 512)))
		return NULL;
	if (d->dp_flags & (DP_WSAME|DP_DISCARD|DP_ZEROES)) {
		if (!expect(peer_device, d->bi_size <= (DRBD_MAX_BBIO_SECTORS << 9)))
			return NULL;
	} else if (!expect(peer_device, d->bi_size <= DRBD_MAX_BIO_SIZE))
		return NULL;

	/* even though we trust our peer,
	 * we sometimes have to double check. */
	if (d->sector + (d->bi_size>>9) > capacity) {
		drbd_err(device, "request from peer beyond end of local disk: "
			"capacity: %llus < sector: %llus + size: %u\n",
			capacity, d->sector, d->bi_size);
		return NULL;
	}

	peer_req = drbd_alloc_peer_req(peer_device, GFP_TRY);
	if (!peer_req)
		return NULL;
	peer_req->i.size = d->bi_size; /* storage size */
	peer_req->i.sector = d->sector;
	peer_req->block_id = d->block_id;

	peer_req->flags |= EE_WRITE;
	if (d->length == 0)
		return peer_req;

	err = tr_ops->recv_pages(transport, &peer_req->page_chain, d->length - d->digest_size);
	if (err)
		goto fail;

	if (drbd_insert_fault(device, DRBD_FAULT_RECEIVE)) {
		struct page *page;
		unsigned long *data;
		drbd_err(device, "Fault injection: Corrupting data on receive, sector %llu\n",
				d->sector);
		page = peer_req->page_chain.head;
		data = kmap(page) + page_chain_offset(page);
		data[0] = ~data[0];
		kunmap(page);
	}

	if (d->digest_size) {
		drbd_csum_pages(peer_device->connection->peer_integrity_tfm, peer_req->page_chain.head, dig_vv);
		if (memcmp(dig_in, dig_vv, d->digest_size)) {
			drbd_err(device, "Digest integrity check FAILED: %llus +%u\n",
				d->sector, d->bi_size);
			goto fail;
		}
	}
	peer_device->recv_cnt += d->bi_size >> 9;
	return peer_req;

fail:
	drbd_free_peer_req(peer_req);
	return NULL;
}

static int ignore_remaining_packet(struct drbd_connection *connection, int size)
{
	void *data_to_ignore;

	while (size) {
		int s = min_t(int, size, DRBD_SOCKET_BUFFER_SIZE);
		int rv = drbd_recv(connection, &data_to_ignore, s, 0);
		if (rv < 0)
			return rv;

		size -= rv;
	}

	return 0;
}

static int recv_dless_read(struct drbd_peer_device *peer_device, struct drbd_request *req,
			   sector_t sector, int data_size)
{
	struct bio_vec bvec;
	struct bvec_iter iter;
	struct bio *bio;
	int digest_size, err, expect;
	void *dig_in = peer_device->connection->int_dig_in;
	void *dig_vv = peer_device->connection->int_dig_vv;

	digest_size = 0;
	if (peer_device->connection->peer_integrity_tfm) {
		digest_size = crypto_shash_digestsize(peer_device->connection->peer_integrity_tfm);
		err = drbd_recv_into(peer_device->connection, dig_in, digest_size);
		if (err)
			return err;
		data_size -= digest_size;
	}

	/* optimistically update recv_cnt.  if receiving fails below,
	 * we disconnect anyways, and counters will be reset. */
	peer_device->recv_cnt += data_size >> 9;

	bio = req->master_bio;
	D_ASSERT(peer_device->device, sector == bio->bi_iter.bi_sector);

	bio_for_each_segment(bvec, bio, iter) {
		void *mapped = kmap(bvec.bv_page) + bvec.bv_offset;
		expect = min_t(int, data_size, bvec.bv_len);
		err = drbd_recv_into(peer_device->connection, mapped, expect);
		kunmap(bvec.bv_page);
		if (err)
			return err;
		data_size -= expect;
	}

	if (digest_size) {
		drbd_csum_bio(peer_device->connection->peer_integrity_tfm, bio, dig_vv);
		if (memcmp(dig_in, dig_vv, digest_size)) {
			drbd_err(peer_device, "Digest integrity check FAILED. Broken NICs?\n");
			return -EINVAL;
		}
	}

	D_ASSERT(peer_device->device, data_size == 0);
	return 0;
}

/*
 * e_end_resync_block() is called in ack_sender context via
 * drbd_finish_peer_reqs().
 */
static int e_end_resync_block(struct drbd_work *w, int unused)
{
	struct drbd_peer_request *peer_req =
		container_of(w, struct drbd_peer_request, w);
	struct drbd_peer_device *peer_device = peer_req->peer_device;
	struct drbd_device *device = peer_device->device;
	sector_t sector = peer_req->i.sector;
	int err;

	D_ASSERT(device, drbd_interval_empty(&peer_req->i));

	if (likely((peer_req->flags & EE_WAS_ERROR) == 0)) {
		drbd_set_in_sync(peer_device, sector, peer_req->i.size);
		err = drbd_send_ack(peer_device, P_RS_WRITE_ACK, peer_req);
	} else {
		/* Record failure to sync */
		drbd_rs_failed_io(peer_device, sector, peer_req->i.size);

		err  = drbd_send_ack(peer_device, P_NEG_ACK, peer_req);
	}
	dec_unacked(peer_device);

	return err;
}

static int recv_resync_read(struct drbd_peer_device *peer_device,
			    struct drbd_peer_request_details *d) __releases(local)
{
	struct drbd_device *device = peer_device->device;
	struct drbd_peer_request *peer_req;
	unsigned int size;
	sector_t sector;
	int err;
	u64 im;

	peer_req = read_in_block(peer_device, d);
	if (!peer_req)
		return -EIO;

	if (test_bit(UNSTABLE_RESYNC, &peer_device->flags))
		clear_bit(STABLE_RESYNC, &device->flags);

	dec_rs_pending(peer_device);

	inc_unacked(peer_device);
	/* corresponding dec_unacked() in e_end_resync_block()
	 * respective _drbd_clear_done_ee */

	peer_req->w.cb = e_end_resync_block;
	peer_req->opf = REQ_OP_WRITE;
	peer_req->submit_jif = jiffies;

	spin_lock_irq(&device->resource->req_lock);
	list_add_tail(&peer_req->w.list, &peer_device->connection->sync_ee);
	spin_unlock_irq(&device->resource->req_lock);

	atomic_add(d->bi_size >> 9, &device->rs_sect_ev);

	/* Setting all peer out of sync here. Sync source peer will be set
	   in sync when the write completes. Other peers will be set in
	   sync by the sync source with a P_PEERS_IN_SYNC packet soon. */
	sector = peer_req->i.sector;
	size = peer_req->i.size;
	drbd_set_all_out_of_sync(device, sector, size);

	err = drbd_submit_peer_request(peer_req);
	if (err)
		goto out;
	peer_req = NULL; /* since submitted, might be destroyed already */

	for_each_peer_device_ref(peer_device, im, device) {
		enum drbd_repl_state repl_state = peer_device->repl_state[NOW];
		if (repl_state == L_WF_BITMAP_S || repl_state == L_SYNC_SOURCE || repl_state == L_PAUSED_SYNC_S)
			drbd_send_out_of_sync(peer_device, sector, size);
	}
	return 0;
out:
	/* don't care for the reason here */
	drbd_err(device, "submit failed, triggering re-connect\n");
	spin_lock_irq(&device->resource->req_lock);
	list_del(&peer_req->w.list);
	spin_unlock_irq(&device->resource->req_lock);

	drbd_free_peer_req(peer_req);
	return err;
}

static struct drbd_request *
find_request(struct drbd_device *device, struct rb_root *root, u64 id,
	     sector_t sector, bool missing_ok, const char *func)
{
	struct drbd_request *req;

	/* Request object according to our peer */
	req = (struct drbd_request *)(unsigned long)id;
	if (drbd_contains_interval(root, sector, &req->i) && req->i.local)
		return req;
	if (!missing_ok) {
		drbd_err(device, "%s: failed to find request 0x%lx, sector %llus\n", func,
			(unsigned long)id, (unsigned long long)sector);
	}
	return NULL;
}

static int receive_DataReply(struct drbd_connection *connection, struct packet_info *pi)
{
	struct drbd_peer_device *peer_device;
	struct drbd_device *device;
	struct drbd_request *req;
	sector_t sector;
	int err;
	struct p_data *p = pi->data;

	peer_device = conn_peer_device(connection, pi->vnr);
	if (!peer_device)
		return -EIO;
	device = peer_device->device;

	sector = be64_to_cpu(p->sector);

	spin_lock_irq(&device->resource->req_lock);
	req = find_request(device, &device->read_requests, p->block_id, sector, false, __func__);
	spin_unlock_irq(&device->resource->req_lock);
	if (unlikely(!req))
		return -EIO;

	err = recv_dless_read(peer_device, req, sector, pi->size);
	if (!err)
		req_mod(req, DATA_RECEIVED, peer_device);
	/* else: nothing. handled from drbd_disconnect...
	 * I don't think we may complete this just yet
	 * in case we are "on-disconnect: freeze" */

	return err;
}

/**
 * _drbd_send_ack() - Sends an ack packet
 * @device:	DRBD device.
 * @cmd:	Packet command code.
 * @sector:	sector, needs to be in big endian byte order
 * @blksize:	size in byte, needs to be in big endian byte order
 * @block_id:	Id, big endian byte order
 */
static int _drbd_send_ack(struct drbd_peer_device *peer_device, enum drbd_packet cmd,
			  u64 sector, u32 blksize, u64 block_id)
{
	struct p_block_ack *p;

	if (peer_device->repl_state[NOW] < L_ESTABLISHED)
		return -EIO;

	p = drbd_prepare_command(peer_device, sizeof(*p), CONTROL_STREAM);
	if (!p)
		return -EIO;
	p->sector = sector;
	p->block_id = block_id;
	p->blksize = blksize;
	p->seq_num = cpu_to_be32(atomic_inc_return(&peer_device->packet_seq));
	return drbd_send_command(peer_device, cmd, CONTROL_STREAM);
}

static int drbd_send_ack_dp(struct drbd_peer_device *peer_device, enum drbd_packet cmd,
		  struct drbd_peer_request_details *d)
{
	return _drbd_send_ack(peer_device, cmd,
			      cpu_to_be64(d->sector),
			      cpu_to_be32(d->bi_size),
			      d->block_id);
}

static void drbd_send_ack_rp(struct drbd_peer_device *peer_device, enum drbd_packet cmd,
		      struct p_block_req *rp)
{
	_drbd_send_ack(peer_device, cmd, rp->sector, rp->blksize, rp->block_id);
}

/**
 * drbd_send_ack() - Sends an ack packet
 * @device:	DRBD device
 * @cmd:	packet command code
 * @peer_req:	peer request
 */
int drbd_send_ack(struct drbd_peer_device *peer_device, enum drbd_packet cmd,
		  struct drbd_peer_request *peer_req)
{
	return _drbd_send_ack(peer_device, cmd,
			      cpu_to_be64(peer_req->i.sector),
			      cpu_to_be32(peer_req->i.size),
			      peer_req->block_id);
}

/* This function misuses the block_id field to signal if the blocks
 * are is sync or not. */
int drbd_send_ack_ex(struct drbd_peer_device *peer_device, enum drbd_packet cmd,
		     sector_t sector, int blksize, u64 block_id)
{
	return _drbd_send_ack(peer_device, cmd,
			      cpu_to_be64(sector),
			      cpu_to_be32(blksize),
			      cpu_to_be64(block_id));
}

static int receive_RSDataReply(struct drbd_connection *connection, struct packet_info *pi)
{
	struct drbd_peer_request_details d;
	struct drbd_peer_device *peer_device;
	struct drbd_device *device;
	int err;

	p_req_detail_from_pi(connection, &d, pi);
	pi->data = NULL;

	peer_device = conn_peer_device(connection, pi->vnr);
	if (!peer_device)
		return -EIO;
	device = peer_device->device;

	D_ASSERT(device, d.block_id == ID_SYNCER);

	if (get_ldev(device)) {
		err = recv_resync_read(peer_device, &d);
		if (err)
			put_ldev(device);
	} else {
		if (drbd_ratelimit())
			drbd_err(device, "Cannot write resync data to local disk.\n");

		err = ignore_remaining_packet(connection, pi->size);

		drbd_send_ack_dp(peer_device, P_NEG_ACK, &d);
	}

	rs_sectors_came_in(peer_device, d.bi_size);

	return err;
}

static void restart_conflicting_writes(struct drbd_peer_request *peer_req)
{
	struct drbd_interval *i;
	struct drbd_request *req;
	struct drbd_device *device = peer_req->peer_device->device;
	const sector_t sector = peer_req->i.sector;
	const unsigned int size = peer_req->i.size;

	drbd_for_each_overlap(i, &device->write_requests, sector, size) {
		if (!i->local)
			continue;
		req = container_of(i, struct drbd_request, i);
		if ((req->local_rq_state & RQ_LOCAL_PENDING) ||
		   !(req->local_rq_state & RQ_POSTPONED))
			continue;
		/* as it is RQ_POSTPONED, this will cause it to
		 * be queued on the retry workqueue. */
		__req_mod(req, DISCARD_WRITE, peer_req->peer_device, NULL);
	}
}

/*
 * e_end_block() is called in ack_sender context via drbd_finish_peer_reqs().
 */
static int e_end_block(struct drbd_work *w, int cancel)
{
	struct drbd_peer_request *peer_req =
		container_of(w, struct drbd_peer_request, w);
	struct drbd_peer_device *peer_device = peer_req->peer_device;
	struct drbd_device *device = peer_device->device;
	sector_t sector = peer_req->i.sector;
	struct drbd_epoch *epoch;
	int err = 0, pcmd;

	if (peer_req->flags & EE_IS_BARRIER) {
		epoch = previous_epoch(peer_device->connection, peer_req->epoch);
		if (epoch)
			drbd_may_finish_epoch(peer_device->connection, epoch, EV_BARRIER_DONE + (cancel ? EV_CLEANUP : 0));
	}

	if (peer_req->flags & EE_SEND_WRITE_ACK) {
		if (unlikely(peer_req->flags & EE_WAS_ERROR)) {
			pcmd = P_NEG_ACK;
			/* we expect it to be marked out of sync anyways...
			 * maybe assert this?  */
		} else if (peer_device->repl_state[NOW] >= L_SYNC_SOURCE &&
			   peer_device->repl_state[NOW] <= L_PAUSED_SYNC_T &&
			   peer_req->flags & EE_MAY_SET_IN_SYNC) {
			pcmd = P_RS_WRITE_ACK;
			drbd_set_in_sync(peer_device, sector, peer_req->i.size);
		} else
			pcmd = P_WRITE_ACK;
		err = drbd_send_ack(peer_device, pcmd, peer_req);
		dec_unacked(peer_device);
	}

	/* we delete from the conflict detection hash _after_ we sent out the
	 * P_WRITE_ACK / P_NEG_ACK, to get the sequence number right.  */
	if (peer_req->flags & EE_IN_INTERVAL_TREE) {
		spin_lock_irq(&device->resource->req_lock);
		D_ASSERT(device, !drbd_interval_empty(&peer_req->i));
		drbd_remove_peer_req_interval(device, peer_req);
		if (peer_req->flags & EE_RESTART_REQUESTS)
			restart_conflicting_writes(peer_req);
		spin_unlock_irq(&device->resource->req_lock);
	} else
		D_ASSERT(device, drbd_interval_empty(&peer_req->i));

	drbd_may_finish_epoch(peer_device->connection, peer_req->epoch, EV_PUT + (cancel ? EV_CLEANUP : 0));

	return err;
}

static int e_send_ack(struct drbd_work *w, enum drbd_packet ack)
{
	struct drbd_peer_request *peer_req =
		container_of(w, struct drbd_peer_request, w);
	struct drbd_peer_device *peer_device = peer_req->peer_device;
	int err;

	err = drbd_send_ack(peer_device, ack, peer_req);
	dec_unacked(peer_device);

	return err;
}

static int e_send_discard_write(struct drbd_work *w, int unused)
{
	return e_send_ack(w, P_SUPERSEDED);
}

static int e_send_retry_write(struct drbd_work *w, int unused)
{

	struct drbd_peer_request *peer_request =
		container_of(w, struct drbd_peer_request, w);
	struct drbd_connection *connection = peer_request->peer_device->connection;

	return e_send_ack(w, connection->agreed_pro_version >= 100 ?
			     P_RETRY_WRITE : P_SUPERSEDED);
}

static bool seq_greater(u32 a, u32 b)
{
	/*
	 * We assume 32-bit wrap-around here.
	 * For 24-bit wrap-around, we would have to shift:
	 *  a <<= 8; b <<= 8;
	 */
	return (s32)a - (s32)b > 0;
}

static u32 seq_max(u32 a, u32 b)
{
	return seq_greater(a, b) ? a : b;
}

static void update_peer_seq(struct drbd_peer_device *peer_device, unsigned int peer_seq)
{
	unsigned int newest_peer_seq;

	if (test_bit(RESOLVE_CONFLICTS, &peer_device->connection->transport.flags)) {
		spin_lock(&peer_device->peer_seq_lock);
		newest_peer_seq = seq_max(peer_device->peer_seq, peer_seq);
		peer_device->peer_seq = newest_peer_seq;
		spin_unlock(&peer_device->peer_seq_lock);
		/* wake up only if we actually changed peer_device->peer_seq */
		if (peer_seq == newest_peer_seq)
			wake_up(&peer_device->device->seq_wait);
	}
}

static inline int overlaps(sector_t s1, int l1, sector_t s2, int l2)
{
	return !((s1 + (l1>>9) <= s2) || (s1 >= s2 + (l2>>9)));
}

/* maybe change sync_ee into interval trees as well? */
static bool overlapping_resync_write(struct drbd_connection *connection, struct drbd_peer_request *peer_req)
{
	struct drbd_peer_request *rs_req;
	bool rv = false;

	/* Now only called in the fallback compatibility path, when the peer is
	 * DRBD version 8, which also means it is the only peer.
	 * If we wanted to use this in a scenario where we could potentially
	 * have in-flight resync writes from multiple peers, we'd need to
	 * iterate over all connections.
	 * Fortunately we don't have to, because we have now mutually excluded
	 * resync and application activity on a particular region using
	 * device->act_log and peer_device->resync_lru.
	 */
	spin_lock_irq(&connection->resource->req_lock);
	list_for_each_entry(rs_req, &connection->sync_ee, w.list) {
		if (rs_req->peer_device != peer_req->peer_device)
			continue;
		if (overlaps(peer_req->i.sector, peer_req->i.size,
			     rs_req->i.sector, rs_req->i.size)) {
			rv = true;
			break;
		}
	}
	spin_unlock_irq(&connection->resource->req_lock);

	return rv;
}

/* Called from receive_Data.
 * Synchronize packets on sock with packets on msock.
 *
 * This is here so even when a P_DATA packet traveling via sock overtook an Ack
 * packet traveling on msock, they are still processed in the order they have
 * been sent.
 *
 * Note: we don't care for Ack packets overtaking P_DATA packets.
 *
 * In case packet_seq is larger than peer_device->peer_seq number, there are
 * outstanding packets on the msock. We wait for them to arrive.
 * In case we are the logically next packet, we update peer_device->peer_seq
 * ourselves. Correctly handles 32bit wrap around.
 *
 * Assume we have a 10 GBit connection, that is about 1<<30 byte per second,
 * about 1<<21 sectors per second. So "worst" case, we have 1<<3 == 8 seconds
 * for the 24bit wrap (historical atomic_t guarantee on some archs), and we have
 * 1<<9 == 512 seconds aka ages for the 32bit wrap around...
 *
 * returns 0 if we may process the packet,
 * -ERESTARTSYS if we were interrupted (by disconnect signal). */
static int wait_for_and_update_peer_seq(struct drbd_peer_device *peer_device, const u32 peer_seq)
{
	struct drbd_connection *connection = peer_device->connection;
	DEFINE_WAIT(wait);
	long timeout;
	int ret = 0, tp;

	if (!test_bit(RESOLVE_CONFLICTS, &connection->transport.flags))
		return 0;

	spin_lock(&peer_device->peer_seq_lock);
	for (;;) {
		if (!seq_greater(peer_seq - 1, peer_device->peer_seq)) {
			peer_device->peer_seq = seq_max(peer_device->peer_seq, peer_seq);
			break;
		}

		if (signal_pending(current)) {
			ret = -ERESTARTSYS;
			break;
		}

		rcu_read_lock();
		tp = rcu_dereference(connection->transport.net_conf)->two_primaries;
		rcu_read_unlock();

		if (!tp)
			break;

		/* Only need to wait if two_primaries is enabled */
		prepare_to_wait(&peer_device->device->seq_wait, &wait, TASK_INTERRUPTIBLE);
		spin_unlock(&peer_device->peer_seq_lock);
		rcu_read_lock();
		timeout = rcu_dereference(connection->transport.net_conf)->ping_timeo*HZ/10;
		rcu_read_unlock();
		timeout = schedule_timeout(timeout);
		spin_lock(&peer_device->peer_seq_lock);
		if (!timeout) {
			ret = -ETIMEDOUT;
			drbd_err(peer_device, "Timed out waiting for missing ack packets; disconnecting\n");
			break;
		}
	}
	spin_unlock(&peer_device->peer_seq_lock);
	finish_wait(&peer_device->device->seq_wait, &wait);
	return ret;
}

static unsigned long wire_flags_to_bio_op(u32 dpf)
{
	if (dpf & DP_ZEROES)
		return REQ_OP_WRITE_ZEROES;
	if (dpf & DP_DISCARD)
		return REQ_OP_DISCARD;
	if (dpf & DP_WSAME)
		return REQ_OP_WRITE_SAME;
	else
		return REQ_OP_WRITE;
}

/* see also bio_flags_to_wire() */
static unsigned long wire_flags_to_bio(struct drbd_connection *connection, u32 dpf)
{
	unsigned long opf = wire_flags_to_bio_op(dpf) |
		(dpf & DP_RW_SYNC ? REQ_SYNC : 0);

	/* we used to communicate one bit only in older DRBD */
	if (connection->agreed_pro_version >= 95)
		opf |= (dpf & DP_FUA ? REQ_FUA : 0) |
			    (dpf & DP_FLUSH ? REQ_PREFLUSH : 0);

	return opf;
}

static void fail_postponed_requests(struct drbd_peer_request *peer_req)
{
	struct drbd_device *device = peer_req->peer_device->device;
	struct drbd_interval *i;
	const sector_t sector = peer_req->i.sector;
	const unsigned int size = peer_req->i.size;

    repeat:
	drbd_for_each_overlap(i, &device->write_requests, sector, size) {
		struct drbd_request *req;
		struct bio_and_error m;

		if (!i->local)
			continue;
		req = container_of(i, struct drbd_request, i);
		if (!(req->local_rq_state & RQ_POSTPONED))
			continue;
		req->local_rq_state &= ~RQ_POSTPONED;
		__req_mod(req, NEG_ACKED, peer_req->peer_device, &m);
		spin_unlock_irq(&device->resource->req_lock);
		if (m.bio)
			complete_master_bio(device, &m);
		spin_lock_irq(&device->resource->req_lock);
		goto repeat;
	}
}

static int handle_write_conflicts(struct drbd_peer_request *peer_req)
{
	struct drbd_peer_device *peer_device = peer_req->peer_device;
	struct drbd_device *device = peer_device->device;
	struct drbd_connection *connection = peer_device->connection;
	bool resolve_conflicts = test_bit(RESOLVE_CONFLICTS, &connection->transport.flags);
	sector_t sector = peer_req->i.sector;
	const unsigned int size = peer_req->i.size;
	struct drbd_interval *i;
	bool equal;
	int err;

	/*
	 * Inserting the peer request into the write_requests tree will prevent
	 * new conflicting local requests from being added.
	 */
	drbd_insert_interval(&device->write_requests, &peer_req->i);
	peer_req->flags |= EE_IN_INTERVAL_TREE;

    repeat:
	drbd_for_each_overlap(i, &device->write_requests, sector, size) {
		if (i == &peer_req->i)
			continue;
		if (i->completed)
			continue;

		if (!i->local) {
			/*
			 * Our peer has sent a conflicting remote request; this
			 * should not happen in a two-node setup.  Wait for the
			 * earlier peer request to complete.
			 */
			err = drbd_wait_misc(device, peer_device, i);
			if (err)
				goto out;
			goto repeat;
		}

		equal = i->sector == sector && i->size == size;
		if (resolve_conflicts) {
			/*
			 * If the peer request is fully contained within the
			 * overlapping request, it can be discarded; otherwise,
			 * it will be retried once all overlapping requests
			 * have completed.
			 */
			bool discard = i->sector <= sector && i->sector +
				       (i->size >> 9) >= sector + (size >> 9);

			if (!equal)
				drbd_alert(device, "Concurrent writes detected: "
					       "local=%llus +%u, remote=%llus +%u, "
					       "assuming %s came first\n",
					  (unsigned long long)i->sector, i->size,
					  (unsigned long long)sector, size,
					  discard ? "local" : "remote");

			peer_req->w.cb = discard ? e_send_discard_write :
						   e_send_retry_write;
			atomic_inc(&connection->done_ee_cnt);
			list_add_tail(&peer_req->w.list, &connection->done_ee);
			queue_work(connection->ack_sender, &connection->send_acks_work);

			err = -ENOENT;
			goto out;
		} else {
			struct drbd_request *req =
				container_of(i, struct drbd_request, i);

			if (!equal)
				drbd_alert(device, "Concurrent writes detected: "
					       "local=%llus +%u, remote=%llus +%u\n",
					  (unsigned long long)i->sector, i->size,
					  (unsigned long long)sector, size);

			if (req->local_rq_state & RQ_LOCAL_PENDING ||
			    !(req->local_rq_state & RQ_POSTPONED)) {
				/*
				 * Wait for the node with the discard flag to
				 * decide if this request will be discarded or
				 * retried.  Requests that are discarded will
				 * disappear from the write_requests tree.
				 *
				 * In addition, wait for the conflicting
				 * request to finish locally before submitting
				 * the conflicting peer request.
				 */
				err = drbd_wait_misc(device, NULL, &req->i);
				if (err) {
					begin_state_change_locked(connection->resource, CS_HARD);
					__change_cstate(connection, C_TIMEOUT);
					end_state_change_locked(connection->resource);
					fail_postponed_requests(peer_req);
					goto out;
				}
				goto repeat;
			}
			/*
			 * Remember to restart the conflicting requests after
			 * the new peer request has completed.
			 */
			peer_req->flags |= EE_RESTART_REQUESTS;
		}
	}
	err = 0;

    out:
	if (err)
		drbd_remove_peer_req_interval(device, peer_req);
	return err;
}

static void drbd_queue_peer_request(struct drbd_device *device, struct drbd_peer_request *peer_req)
{
	atomic_inc(&device->wait_for_actlog);
	spin_lock_irq(&device->resource->req_lock);
	list_add_tail(&peer_req->wait_for_actlog, &device->submit.peer_writes);
	spin_unlock_irq(&device->resource->req_lock);
	queue_work(device->submit.wq, &device->submit.worker);
	/* do_submit() may sleep internally on al_wait, too */
	wake_up(&device->al_wait);
}

/* FIXME
 * TODO grab the device->al_lock *once*, and check:
 *     if possible, non-blocking get the reference(s),
 *     if transaction is required, queue them up,
 *        AND account for the queued up worst-case slot consumption
 *     if available slots, corrected by other accounting, suggest
 *        that we might block on this now or later,
 *        *FIRST* drain, then flush, then send P_CONFIRM_STABLE,
 *        then wait for available slots to be sufficient.
 */
static enum { DRBD_PAL_QUEUE, DRBD_PAL_DISCONNECTED, DRBD_PAL_SUBMIT }
prepare_activity_log(struct drbd_peer_request *peer_req)
{
	struct drbd_peer_device *peer_device = peer_req->peer_device;
	struct drbd_connection *connection = peer_device->connection;
	struct drbd_device *device = peer_device->device;

	struct lru_cache *al;
	int nr_al_extents = interval_to_al_extents(&peer_req->i);
	int nr, used, ecnt;
	int ret = DRBD_PAL_SUBMIT;

	/* In protocol < 110 (which is compat mode 8.4 <-> 9.0),
	 * we must not block in the activity log here, that would
	 * deadlock during an ongoing resync with the drbd_rs_begin_io
	 * we did when receiving the resync request.
	 *
	 * We still need to update the activity log, if ours is the
	 * only remaining disk, in which case there cannot be a resync,
	 * and the deadlock paths cannot be taken.
	 */
	if (connection->agreed_pro_version < 110 &&
	    peer_device->disk_state[NOW] >= D_INCONSISTENT)
		return DRBD_PAL_SUBMIT;

	/* Let the activity log know we are about to use it.
	 * See also drbd_request_prepare() for the "request" entry point. */
	ecnt = atomic_add_return(nr_al_extents, &device->wait_for_actlog_ecnt);

	spin_lock_irq(&device->al_lock);
	al = device->act_log;
	nr = al->nr_elements;
	used = al->used;
	spin_unlock_irq(&device->al_lock);

	/* note: due to the slight delay between being accounted in "used" after
	 * being committed to the activity log with drbd_al_begin_io_commit(),
	 * and being subtracted from "wait_for_actlog_ecnt" in __drbd_submit_peer_request(),
	 * this can err, but only on the conservative side (overestimating ecnt). */
	if (ecnt > nr - used) {
		conn_wait_active_ee_empty_or_disconnect(connection);
		drbd_flush_after_epoch(connection, NULL);
		conn_wait_done_ee_empty_or_disconnect(connection);

		/* would this peer even understand me? */
		if (connection->agreed_pro_version >= 114)
			drbd_send_confirm_stable(peer_req);

		if  (drbd_al_begin_io_for_peer(peer_device, &peer_req->i))
			ret = DRBD_PAL_DISCONNECTED;
	} else if (nr_al_extents != 1 || !drbd_al_begin_io_fastpath(device, &peer_req->i)) {
		ret = DRBD_PAL_QUEUE;
	}
	if (ret == DRBD_PAL_SUBMIT)
		peer_req->flags |= EE_IN_ACTLOG;
	if (ret != DRBD_PAL_QUEUE)
		atomic_sub(nr_al_extents, &device->wait_for_actlog_ecnt);

	return ret;
}

/* mirrored write */
static int receive_Data(struct drbd_connection *connection, struct packet_info *pi)
{
	struct drbd_peer_device *peer_device;
	struct drbd_device *device;
	struct net_conf *nc;
	struct drbd_peer_request *peer_req;
	struct drbd_peer_request_details d;
	int err, tp;

	peer_device = conn_peer_device(connection, pi->vnr);
	if (!peer_device)
		return -EIO;
	device = peer_device->device;

	if (pi->cmd == P_TRIM)
		D_ASSERT(peer_device, pi->size == 0);

	p_req_detail_from_pi(connection, &d, pi);
	pi->data = NULL;

	if (!get_ldev(device)) {
		int err2;

		err = wait_for_and_update_peer_seq(peer_device, d.peer_seq);
		drbd_send_ack_dp(peer_device, P_NEG_ACK, &d);
		atomic_inc(&connection->current_epoch->epoch_size);
		err2 = ignore_remaining_packet(connection, pi->size);
		if (!err)
			err = err2;
		return err;
	}

	/*
	 * Corresponding put_ldev done either below (on various errors), or in
	 * drbd_peer_request_endio, if we successfully submit the data at the
	 * end of this function.
	 */

	peer_req = read_in_block(peer_device, &d);
	if (!peer_req) {
		put_ldev(device);
		return -EIO;
	}
	if (pi->cmd == P_TRIM)
		peer_req->flags |= EE_TRIM;
	else if (pi->cmd == P_ZEROES)
		peer_req->flags |= EE_ZEROOUT;
	else if (pi->cmd == P_WSAME)
		peer_req->flags |= EE_WRITE_SAME;

	peer_req->dagtag_sector = connection->last_dagtag_sector + (peer_req->i.size >> 9);
	connection->last_dagtag_sector = peer_req->dagtag_sector;

	peer_req->w.cb = e_end_block;
	peer_req->submit_jif = jiffies;
	peer_req->flags |= EE_APPLICATION;

	peer_req->opf = wire_flags_to_bio(connection, d.dp_flags);
	if (pi->cmd == P_TRIM) {
		D_ASSERT(peer_device, peer_req->i.size > 0);
		D_ASSERT(peer_device, d.dp_flags & DP_DISCARD);
		D_ASSERT(peer_device, peer_req_op(peer_req) == REQ_OP_DISCARD);
		D_ASSERT(peer_device, peer_req->page_chain.head == NULL);
		D_ASSERT(peer_device, peer_req->page_chain.nr_pages == 0);
		/* need to play safe: an older DRBD sender
		 * may mean zero-out while sending P_TRIM. */
		if (0 == (connection->agreed_features & DRBD_FF_WZEROES))
			peer_req->flags |= EE_ZEROOUT;
	} else if (pi->cmd == P_ZEROES) {
		D_ASSERT(peer_device, peer_req->i.size > 0);
		D_ASSERT(peer_device, d.dp_flags & DP_ZEROES);
		D_ASSERT(peer_device, peer_req_op(peer_req) == REQ_OP_WRITE_ZEROES);
		D_ASSERT(peer_device, peer_req->page_chain.head == NULL);
		D_ASSERT(peer_device, peer_req->page_chain.nr_pages == 0);
		/* Do (not) pass down BLKDEV_ZERO_NOUNMAP? */
		if (d.dp_flags & DP_DISCARD)
			peer_req->flags |= EE_TRIM;
	} else if (pi->cmd == P_WSAME) {
		D_ASSERT(peer_device, peer_req->i.size > 0);
		D_ASSERT(peer_device, peer_req_op(peer_req) == REQ_OP_WRITE_SAME);
		D_ASSERT(peer_device, peer_req->page_chain.head != NULL);
	} else if (peer_req->page_chain.head == NULL) {
		/* Actually, this must not happen anymore,
		 * "empty" flushes are mapped to P_BARRIER,
		 * and should never end up here.
		 * Compat with old DRBD? */
		D_ASSERT(device, peer_req->i.size == 0);
		D_ASSERT(device, d.dp_flags & DP_FLUSH);
	} else {
		D_ASSERT(peer_device, peer_req->i.size > 0);
		D_ASSERT(peer_device, peer_req_op(peer_req) == REQ_OP_WRITE);
	}

	if (d.dp_flags & DP_MAY_SET_IN_SYNC)
		peer_req->flags |= EE_MAY_SET_IN_SYNC;

	spin_lock(&connection->epoch_lock);
	peer_req->epoch = connection->current_epoch;
	atomic_inc(&peer_req->epoch->epoch_size);
	atomic_inc(&peer_req->epoch->active);
	if (peer_req->epoch->oldest_unconfirmed_peer_req == NULL)
		peer_req->epoch->oldest_unconfirmed_peer_req = peer_req;

	if (connection->resource->write_ordering == WO_BIO_BARRIER &&
	    atomic_read(&peer_req->epoch->epoch_size) == 1) {
		struct drbd_epoch *epoch;
		/* Issue a barrier if we start a new epoch, and the previous epoch
		   was not a epoch containing a single request which already was
		   a Barrier. */
		epoch = list_entry(peer_req->epoch->list.prev, struct drbd_epoch, list);
		if (epoch == peer_req->epoch) {
			set_bit(DE_CONTAINS_A_BARRIER, &peer_req->epoch->flags);
			peer_req->opf |= REQ_PREFLUSH | REQ_FUA;
			peer_req->flags |= EE_IS_BARRIER;
		} else {
			if (atomic_read(&epoch->epoch_size) > 1 ||
			    !test_bit(DE_CONTAINS_A_BARRIER, &epoch->flags)) {
				set_bit(DE_BARRIER_IN_NEXT_EPOCH_ISSUED, &epoch->flags);
				set_bit(DE_CONTAINS_A_BARRIER, &peer_req->epoch->flags);
				peer_req->opf |= REQ_PREFLUSH | REQ_FUA;
				peer_req->flags |= EE_IS_BARRIER;
			}
		}
	}
	spin_unlock(&connection->epoch_lock);

	rcu_read_lock();
	nc = rcu_dereference(connection->transport.net_conf);
	tp = nc->two_primaries;
	if (connection->agreed_pro_version < 100) {
		switch (nc->wire_protocol) {
		case DRBD_PROT_C:
			d.dp_flags |= DP_SEND_WRITE_ACK;
			break;
		case DRBD_PROT_B:
			d.dp_flags |= DP_SEND_RECEIVE_ACK;
			break;
		}
	}
	rcu_read_unlock();

	if (d.dp_flags & DP_SEND_WRITE_ACK) {
		peer_req->flags |= EE_SEND_WRITE_ACK;
		inc_unacked(peer_device);
		/* corresponding dec_unacked() in e_end_block()
		 * respective _drbd_clear_done_ee */
	}

	if (d.dp_flags & DP_SEND_RECEIVE_ACK) {
		/* I really don't like it that the receiver thread
		 * sends on the msock, but anyways */
		drbd_send_ack(peer_device, P_RECV_ACK, peer_req);
	}

	if (tp) {
		/* two primaries implies protocol C */
		D_ASSERT(device, d.dp_flags & DP_SEND_WRITE_ACK);
		err = wait_for_and_update_peer_seq(peer_device, d.peer_seq);
		if (err)
			goto out_interrupted;
		spin_lock_irq(&device->resource->req_lock);
		err = handle_write_conflicts(peer_req);
		if (err) {
			spin_unlock_irq(&device->resource->req_lock);
			if (err == -ENOENT) {
				put_ldev(device);
				return 0;
			}
			goto out_interrupted;
		}
	} else {
		update_peer_seq(peer_device, d.peer_seq);
		spin_lock_irq(&device->resource->req_lock);
	}
	/* Added to list here already, so debugfs can find it.
	 * NOTE: active_ee_cnt is only increased *after* we checked we won't
	 * need to wait for current activity to drain in prepare_activity_log()
	 */
	list_add_tail(&peer_req->w.list, &connection->active_ee);
	if (connection->agreed_pro_version >= 110)
		list_add_tail(&peer_req->recv_order, &connection->peer_requests);
	spin_unlock_irq(&device->resource->req_lock);

	if (connection->agreed_pro_version < 110) {
		/* If the peer is DRBD 8, a sync target may need to drain
		 * (overlapping) in-flight resync requests first.
		 * With DRBD 9, the mutually exclusive references in resync lru
		 * and activity log takes care of that already. */
		if (peer_device->repl_state[NOW] == L_SYNC_TARGET)
			wait_event(connection->ee_wait, !overlapping_resync_write(connection, peer_req));
	}

	err = prepare_activity_log(peer_req);
	if (err == DRBD_PAL_DISCONNECTED)
		goto disconnect_during_al_begin_io;

	/* Note: this now may or may not be "hot" in the activity log.
	 * Still, it is the best time to record that we need to set the
	 * out-of-sync bit, if we delay that until drbd_submit_peer_request(),
	 * we may introduce a race with some re-attach on the peer.
	 * Unless we want to guarantee that we drain all in-flight IO
	 * whenever we receive a state change. Which I'm not sure about.
	 * Use the EE_SET_OUT_OF_SYNC flag, to be acted on just before
	 * the actual submit, when we can be sure it is "hot".
	 */
	if (peer_device->disk_state[NOW] < D_INCONSISTENT) {
		peer_req->flags &= ~EE_MAY_SET_IN_SYNC;
		peer_req->flags |= EE_SET_OUT_OF_SYNC;
	}

	atomic_inc(&connection->active_ee_cnt);

	if (err == DRBD_PAL_QUEUE) {
		drbd_queue_peer_request(device, peer_req);
		return 0;
	}

	err = drbd_submit_peer_request(peer_req);
	if (!err)
		return 0;

	/* don't care for the reason here */
	drbd_err(peer_device, "submit failed, triggering re-connect\n");
	drbd_al_complete_io(device, &peer_req->i);

disconnect_during_al_begin_io:
	spin_lock_irq(&device->resource->req_lock);
	list_del(&peer_req->w.list);
	list_del_init(&peer_req->recv_order);
	drbd_remove_peer_req_interval(device, peer_req);
	spin_unlock_irq(&device->resource->req_lock);

out_interrupted:
	if (peer_req->flags & EE_SEND_WRITE_ACK)
		dec_unacked(peer_device);
	drbd_may_finish_epoch(connection, peer_req->epoch, EV_PUT + EV_CLEANUP);
	put_ldev(device);
	drbd_free_peer_req(peer_req);
	return err;
}

/*
 * To be called when __drbd_submit_peer_request() fails from submitter
 * workqueue context.  Mimic what happens in the receive_Data() error path,
 * when the submit happens directly in the receiver context.
 */
void drbd_cleanup_after_failed_submit_peer_request(struct drbd_peer_request *peer_req)
{
	struct drbd_peer_device *peer_device = peer_req->peer_device;
	struct drbd_device *device = peer_device->device;
	struct drbd_connection *connection = peer_device->connection;

	if (drbd_ratelimit())
		drbd_err(peer_device, "submit failed, triggering re-connect\n");

	drbd_al_complete_io(device, &peer_req->i);

	spin_lock_irq(&device->resource->req_lock);
	list_del(&peer_req->w.list);
	list_del_init(&peer_req->recv_order);
	drbd_remove_peer_req_interval(device, peer_req);
	spin_unlock_irq(&device->resource->req_lock);

	drbd_may_finish_epoch(connection, peer_req->epoch, EV_PUT + EV_CLEANUP);
	put_ldev(device);
	drbd_free_peer_req(peer_req);
	change_cstate(connection, C_PROTOCOL_ERROR, CS_HARD);
}

/* Possibly "cancel" and forget about all peer_requests that had still been
 * waiting for the activity log (wfa) when the connection to their peer failed,
 * and pretend we never received them.
 */
void drbd_cleanup_peer_requests_wfa(struct drbd_device *device, struct list_head *cleanup)
{
	struct drbd_connection *connection;
	struct drbd_peer_request *peer_req, *pr_tmp;

	spin_lock_irq(&device->resource->req_lock);
	list_for_each_entry(peer_req, cleanup, wait_for_actlog) {
		list_del(&peer_req->w.list); /* should be on the "->active_ee" list */
		atomic_dec(&peer_req->peer_device->connection->active_ee_cnt);
		list_del_init(&peer_req->recv_order);
		drbd_remove_peer_req_interval(device, peer_req);
	}
	spin_unlock_irq(&device->resource->req_lock);

	list_for_each_entry_safe(peer_req, pr_tmp, cleanup, wait_for_actlog) {
		atomic_sub(interval_to_al_extents(&peer_req->i), &device->wait_for_actlog_ecnt);
		atomic_dec(&device->wait_for_actlog);
		if (peer_req->flags & EE_SEND_WRITE_ACK)
			dec_unacked(peer_req->peer_device);
		list_del_init(&peer_req->wait_for_actlog);
		drbd_may_finish_epoch(peer_req->peer_device->connection, peer_req->epoch, EV_PUT | EV_CLEANUP);
		drbd_free_peer_req(peer_req);
		put_ldev(device);
	}
	/* We changed (likely: cleared out) active_ee for "at least one" connection.
	 * We should wake potential waiters, just in case. */
	for_each_connection(connection, device->resource)
		wake_up(&connection->ee_wait);
}

/* We may throttle resync, if the lower device seems to be busy,
 * and current sync rate is above c_min_rate.
 *
 * To decide whether or not the lower device is busy, we use a scheme similar
 * to MD RAID is_mddev_idle(): if the partition stats reveal "significant"
 * (more than 64 sectors) of activity we cannot account for with our own resync
 * activity, it obviously is "busy".
 *
 * The current sync rate used here uses only the most recent two step marks,
 * to have a short time average so we can react faster.
 */
bool drbd_rs_should_slow_down(struct drbd_peer_device *peer_device, sector_t sector,
			      bool throttle_if_app_is_waiting)
{
	bool throttle = drbd_rs_c_min_rate_throttle(peer_device);

	if (!throttle || throttle_if_app_is_waiting)
		return throttle;

	return !drbd_sector_has_priority(peer_device, sector);
}

bool drbd_rs_c_min_rate_throttle(struct drbd_peer_device *peer_device)
{
	struct drbd_device *device = peer_device->device;
	struct hd_struct *part = &device->ldev->backing_bdev->bd_contains->bd_disk->part0;
	unsigned long db, dt, dbdt;
	unsigned int c_min_rate;
	int curr_events;

	rcu_read_lock();
	c_min_rate = rcu_dereference(peer_device->conf)->c_min_rate;
	rcu_read_unlock();

	/* feature disabled? */
	if (c_min_rate == 0)
		return false;

	curr_events = (int)part_stat_read(part, sectors[0])
		+ (int)part_stat_read(part, sectors[1])
		- atomic_read(&device->rs_sect_ev);

	if (atomic_read(&device->ap_actlog_cnt) || curr_events - peer_device->rs_last_events > 64) {
		unsigned long rs_left;
		int i;

		peer_device->rs_last_events = curr_events;

		/* sync speed average over the last 2*DRBD_SYNC_MARK_STEP,
		 * approx. */
		i = (peer_device->rs_last_mark + DRBD_SYNC_MARKS-1) % DRBD_SYNC_MARKS;

		if (peer_device->repl_state[NOW] == L_VERIFY_S || peer_device->repl_state[NOW] == L_VERIFY_T)
			rs_left = peer_device->ov_left;
		else
			rs_left = drbd_bm_total_weight(peer_device) - peer_device->rs_failed;

		dt = ((long)jiffies - (long)peer_device->rs_mark_time[i]) / HZ;
		if (!dt)
			dt++;
		db = peer_device->rs_mark_left[i] - rs_left;
		dbdt = Bit2KB(db/dt);

		if (dbdt > c_min_rate)
			return true;
	}
	return false;
}

static void verify_skipped_block(struct drbd_peer_device *peer_device,
		const sector_t sector, const unsigned int size)
{
	++peer_device->ov_skipped;
	if (peer_device->ov_last_skipped_start + peer_device->ov_last_skipped_size == sector) {
		peer_device->ov_last_skipped_size += size>>9;
	} else {
		ov_skipped_print(peer_device);
		peer_device->ov_last_skipped_start = sector;
		peer_device->ov_last_skipped_size = size>>9;
	}
	verify_progress(peer_device, sector, size);
}

static int receive_DataRequest(struct drbd_connection *connection, struct packet_info *pi)
{
	struct drbd_peer_device *peer_device;
	struct drbd_device *device;
	sector_t sector;
	sector_t capacity;
	struct drbd_peer_request *peer_req;
	struct digest_info *di = NULL;
	int size, verb;
	struct p_block_req *p =	pi->data;
	enum drbd_disk_state min_d_state;
	int err;

	peer_device = conn_peer_device(connection, pi->vnr);
	if (!peer_device)
		return -EIO;
	device = peer_device->device;
	capacity = get_capacity(device->vdisk);

	sector = be64_to_cpu(p->sector);
	size   = be32_to_cpu(p->blksize);

	if (size <= 0 || !IS_ALIGNED(size, 512) || size > DRBD_MAX_BIO_SIZE) {
		drbd_err(peer_device, "%s:%d: sector: %llus, size: %u\n", __FILE__, __LINE__,
				(unsigned long long)sector, size);
		return -EINVAL;
	}
	if (sector + (size>>9) > capacity) {
		drbd_err(peer_device, "%s:%d: sector: %llus, size: %u\n", __FILE__, __LINE__,
				(unsigned long long)sector, size);
		return -EINVAL;
	}

	/* Tell target to have a retry, waiting for the rescheduled
	 * drbd_start_resync to complete. Otherwise the concurrency
	 * of send oos and resync may lead to a data lose. */
	if ((pi->cmd == P_RS_DATA_REQUEST || pi->cmd == P_CSUM_RS_REQUEST) &&
	    peer_device->repl_state[NOW] == L_WF_BITMAP_S) {
		drbd_send_ack_rp(peer_device, P_RS_CANCEL, p);
		return ignore_remaining_packet(connection, pi->size);
	}

	min_d_state = pi->cmd == P_DATA_REQUEST ? D_UP_TO_DATE : D_OUTDATED;
	if (!get_ldev_if_state(device, min_d_state)) {
		verb = 1;
		switch (pi->cmd) {
		case P_DATA_REQUEST:
			drbd_send_ack_rp(peer_device, P_NEG_DREPLY, p);
			break;
		case P_OV_REQUEST:
			verify_skipped_block(peer_device, sector, size);
			drbd_send_ack_rp(peer_device, P_RS_CANCEL, p);
			break;
		case P_RS_THIN_REQ:
		case P_RS_DATA_REQUEST:
		case P_CSUM_RS_REQUEST:
			if (peer_device->repl_state[NOW] == L_PAUSED_SYNC_S) {
				verb = 0;
				drbd_send_ack_rp(peer_device, P_RS_CANCEL, p);
			} else {
				drbd_send_ack_rp(peer_device, P_NEG_RS_DREPLY, p);
			}
			break;
		case P_OV_REPLY:
			verb = 0;
			dec_rs_pending(peer_device);
			drbd_send_ack_ex(peer_device, P_OV_RESULT, sector, size, ID_IN_SYNC);
			break;
		default:
			BUG();
		}
		if (verb && drbd_ratelimit())
			drbd_err(peer_device, "Can not satisfy peer's read request, "
			    "no local data.\n");

		/* drain possibly payload */
		return ignore_remaining_packet(connection, pi->size);
	}

	peer_req = drbd_alloc_peer_req(peer_device, GFP_TRY);
	err = -ENOMEM;
	if (!peer_req)
		goto fail;
	if (size) {
		drbd_alloc_page_chain(&peer_device->connection->transport,
			&peer_req->page_chain, DIV_ROUND_UP(size, PAGE_SIZE), GFP_TRY);
		if (!peer_req->page_chain.head)
			goto fail2;
	}
	peer_req->i.size = size;
	peer_req->i.sector = sector;
	peer_req->block_id = p->block_id;
	peer_req->opf = REQ_OP_READ;
	/* no longer valid, about to call drbd_recv again for the digest... */
	p = pi->data = NULL;


	if (peer_device->repl_state[NOW] == L_AHEAD) {
		if (pi->cmd == P_DATA_REQUEST) {
			/* P_DATA_REQUEST originates from a Primary,
			 * so if I am "Ahead", the Primary would be "Behind":
			 * Can not happen. */
			if (drbd_ratelimit())
				drbd_err(peer_device, "received P_DATA_REQUEST while L_AHEAD\n");
			err = -EINVAL;
			goto fail2;
		}
		if (connection->agreed_pro_version >= 115) {
			switch (pi->cmd) {
			/* case P_DATA_REQUEST: see above, not based on protocol version */
			case P_OV_REQUEST:
				verify_skipped_block(peer_device, sector, size);
				fallthrough;
			case P_RS_DATA_REQUEST:
			case P_RS_THIN_REQ:
			case P_CSUM_RS_REQUEST:
				err = drbd_send_ack(peer_device, P_RS_CANCEL_AHEAD, peer_req);
				goto fail2;
			case P_OV_REPLY:
				/* FIXME how can we cancel these?
				 * just ignore L_AHEAD for now */
				break;
			default:
				BUG();
			}
		}
	}

	switch (pi->cmd) {
	case P_DATA_REQUEST:
		peer_req->w.cb = w_e_end_data_req;
		/* application IO, don't drbd_rs_begin_io */
		peer_req->flags |= EE_APPLICATION;
		goto submit;

	case P_RS_THIN_REQ:
		/* If at some point in the future we have a smart way to
		   find out if this data block is completely deallocated,
		   then we would do something smarter here than reading
		   the block... */
		peer_req->flags |= EE_RS_THIN_REQ;
		fallthrough;
	case P_RS_DATA_REQUEST:
		peer_req->w.cb = w_e_end_rsdata_req;
		break;

	case P_OV_REPLY:
	case P_CSUM_RS_REQUEST:
		di = kmalloc(sizeof(*di) + pi->size, GFP_NOIO);
		err = -ENOMEM;
		if (!di)
			goto fail2;

		di->digest_size = pi->size;
		di->digest = (((char *)di)+sizeof(struct digest_info));

		peer_req->digest = di;
		peer_req->flags |= EE_HAS_DIGEST;

		err = drbd_recv_into(connection, di->digest, pi->size);
		if (err)
			goto fail2;

		if (pi->cmd == P_CSUM_RS_REQUEST) {
			D_ASSERT(device, connection->agreed_pro_version >= 89);
			peer_req->w.cb = w_e_end_csum_rs_req;
			/* remember to report stats in drbd_resync_finished */
			peer_device->use_csums = true;
		} else if (pi->cmd == P_OV_REPLY) {
			/* track progress, we may need to throttle */
			rs_sectors_came_in(peer_device, size);
			peer_req->w.cb = w_e_end_ov_reply;
			dec_rs_pending(peer_device);
			/* drbd_rs_begin_io done when we sent this request,
			 * but accounting still needs to be done. */
			goto submit_for_resync;
		}
		break;

	case P_OV_REQUEST:
		peer_device->ov_position = sector;
		if (peer_device->ov_start_sector == ~(sector_t)0 &&
		    connection->agreed_pro_version >= 90) {
			unsigned long now = jiffies;
			int i;
			peer_device->ov_start_sector = sector;
			peer_device->ov_left = drbd_bm_bits(device) - BM_SECT_TO_BIT(sector);
			peer_device->ov_skipped = 0;
			peer_device->rs_total = peer_device->ov_left;
			peer_device->rs_last_writeout = now;
			for (i = 0; i < DRBD_SYNC_MARKS; i++) {
				peer_device->rs_mark_left[i] = peer_device->ov_left;
				peer_device->rs_mark_time[i] = now;
			}
			drbd_info(device, "Online Verify start sector: %llu\n",
					(unsigned long long)sector);
		}
		peer_req->w.cb = w_e_end_ov_req;
		break;

	default:
		BUG();
	}

	/* Throttle, drbd_rs_begin_io and submit should become asynchronous
	 * wrt the receiver, but it is not as straightforward as it may seem.
	 * Various places in the resync start and stop logic assume resync
	 * requests are processed in order, requeuing this on the worker thread
	 * introduces a bunch of new code for synchronization between threads.
	 *
	 * Unlimited throttling before drbd_rs_begin_io may stall the resync
	 * "forever", throttling after drbd_rs_begin_io will lock that extent
	 * for application writes for the same time.  For now, just throttle
	 * here, where the rest of the code expects the receiver to sleep for
	 * a while, anyways.
	 */

	/* Throttle before drbd_rs_begin_io, as that locks out application IO;
	 * this defers syncer requests for some time, before letting at least
	 * on request through.  The resync controller on the receiving side
	 * will adapt to the incoming rate accordingly.
	 *
	 * We cannot throttle here if remote is Primary/SyncTarget:
	 * we would also throttle its application reads.
	 * In that case, throttling is done on the SyncTarget only.
	 */

	/* Even though this may be a resync request, we do add to "read_ee";
	 * "sync_ee" is only used for resync WRITEs.
	 * Add to list early, so debugfs can find this request
	 * even if we have to sleep below. */
	spin_lock_irq(&device->resource->req_lock);
	list_add_tail(&peer_req->w.list, &connection->read_ee);
	spin_unlock_irq(&device->resource->req_lock);

	update_receiver_timing_details(connection, drbd_rs_should_slow_down);
	if (connection->peer_role[NOW] != R_PRIMARY &&
	    drbd_rs_should_slow_down(peer_device, sector, false))
		schedule_timeout_uninterruptible(HZ/10);

	if (connection->agreed_pro_version >= 110) {
		/* In DRBD9 we may not sleep here in order to avoid deadlocks.
		   Instruct the SyncSource to retry */
		err = drbd_try_rs_begin_io(peer_device, sector, false);
		if (err) {
			if (pi->cmd == P_OV_REQUEST)
				verify_skipped_block(peer_device, sector, size);
			err = drbd_send_ack(peer_device, P_RS_CANCEL, peer_req);
			/* If err is set, we will drop the connection... */
			goto fail3;
		}
	} else {
		update_receiver_timing_details(connection, drbd_rs_begin_io);
		if (drbd_rs_begin_io(peer_device, sector)) {
			err = -EIO;
			goto fail3;
		}
	}

submit_for_resync:
	atomic_add(size >> 9, &device->rs_sect_ev);

submit:
	update_receiver_timing_details(connection, drbd_submit_peer_request);
	inc_unacked(peer_device);
	if (drbd_submit_peer_request(peer_req) == 0)
		return 0;

	/* don't care for the reason here */
	drbd_err(device, "submit failed, triggering re-connect\n");
	err = -EIO;

fail3:
	spin_lock_irq(&device->resource->req_lock);
	list_del(&peer_req->w.list);
	spin_unlock_irq(&device->resource->req_lock);
	/* no drbd_rs_complete_io(), we are dropping the connection anyways */
fail2:
	drbd_free_peer_req(peer_req);
fail:
	put_ldev(device);
	return err;
}

/**
 * drbd_asb_recover_0p  -  Recover after split-brain with no remaining primaries
 */
static enum sync_strategy drbd_asb_recover_0p(struct drbd_peer_device *peer_device) __must_hold(local)
{
	const int node_id = peer_device->device->resource->res_opts.node_id;
	int self, peer;
	enum sync_strategy rv = SPLIT_BRAIN_DISCONNECT;
	unsigned long ch_self, ch_peer;
	enum drbd_after_sb_p after_sb_0p;

	self = drbd_bitmap_uuid(peer_device) & UUID_PRIMARY;
	peer = peer_device->bitmap_uuids[node_id] & UUID_PRIMARY;

	ch_peer = peer_device->dirty_bits;
	ch_self = peer_device->comm_bm_set;

	rcu_read_lock();
	after_sb_0p = rcu_dereference(peer_device->connection->transport.net_conf)->after_sb_0p;
	rcu_read_unlock();
	switch (after_sb_0p) {
	case ASB_CONSENSUS:
	case ASB_DISCARD_SECONDARY:
	case ASB_CALL_HELPER:
	case ASB_VIOLENTLY:
	case ASB_RETRY_CONNECT:
		drbd_err(peer_device, "Configuration error.\n");
		break;
	case ASB_DISCONNECT:
		break;
	case ASB_DISCARD_YOUNGER_PRI:
		if (self == 0 && peer == 1) {
			rv = SYNC_TARGET_USE_BITMAP;
			break;
		}
		if (self == 1 && peer == 0) {
			rv = SYNC_SOURCE_USE_BITMAP;
			break;
		}
		fallthrough;	/* to one of the other strategies */
	case ASB_DISCARD_OLDER_PRI:
		if (self == 0 && peer == 1) {
			rv = SYNC_SOURCE_USE_BITMAP;
			break;
		}
		if (self == 1 && peer == 0) {
			rv = SYNC_TARGET_USE_BITMAP;
			break;
		}
		drbd_warn(peer_device, "Discard younger/older primary did not find a decision\n"
			  "Using discard-least-changes instead\n");
		fallthrough;
	case ASB_DISCARD_ZERO_CHG:
		if (ch_peer == 0 && ch_self == 0) {
			rv = test_bit(RESOLVE_CONFLICTS, &peer_device->connection->transport.flags)
				? SYNC_TARGET_USE_BITMAP : SYNC_SOURCE_USE_BITMAP;
			break;
		} else {
			if (ch_peer == 0) { rv = SYNC_SOURCE_USE_BITMAP; break; }
			if (ch_self == 0) { rv = SYNC_TARGET_USE_BITMAP; break; }
		}
		if (after_sb_0p == ASB_DISCARD_ZERO_CHG)
			break;
		fallthrough;
	case ASB_DISCARD_LEAST_CHG:
		if	(ch_self < ch_peer)
			rv = SYNC_TARGET_USE_BITMAP;
		else if (ch_self > ch_peer)
			rv = SYNC_SOURCE_USE_BITMAP;
		else /* ( ch_self == ch_peer ) */
		     /* Well, then use something else. */
			rv = test_bit(RESOLVE_CONFLICTS, &peer_device->connection->transport.flags)
				? SYNC_TARGET_USE_BITMAP : SYNC_SOURCE_USE_BITMAP;
		break;
	case ASB_DISCARD_LOCAL:
		rv = SYNC_TARGET_USE_BITMAP;
		break;
	case ASB_DISCARD_REMOTE:
		rv = SYNC_SOURCE_USE_BITMAP;
	}

	return rv;
}

/**
 * drbd_asb_recover_1p  -  Recover after split-brain with one remaining primary
 */
static enum sync_strategy drbd_asb_recover_1p(struct drbd_peer_device *peer_device) __must_hold(local)
{
	struct drbd_device *device = peer_device->device;
	struct drbd_connection *connection = peer_device->connection;
	struct drbd_resource *resource = device->resource;
	enum sync_strategy strategy, rv = SPLIT_BRAIN_DISCONNECT;
	enum drbd_after_sb_p after_sb_1p;

	rcu_read_lock();
	after_sb_1p = rcu_dereference(connection->transport.net_conf)->after_sb_1p;
	rcu_read_unlock();
	switch (after_sb_1p) {
	case ASB_DISCARD_YOUNGER_PRI:
	case ASB_DISCARD_OLDER_PRI:
	case ASB_DISCARD_LEAST_CHG:
	case ASB_DISCARD_LOCAL:
	case ASB_DISCARD_REMOTE:
	case ASB_DISCARD_ZERO_CHG:
	case ASB_RETRY_CONNECT:
		drbd_err(device, "Configuration error.\n");
		break;
	case ASB_DISCONNECT:
		break;
	case ASB_CONSENSUS:
		strategy = drbd_asb_recover_0p(peer_device);
		if (strategy == SYNC_TARGET_USE_BITMAP && resource->role[NOW] == R_SECONDARY)
			rv = strategy;
		if (strategy == SYNC_SOURCE_USE_BITMAP && resource->role[NOW] == R_PRIMARY)
			rv = strategy;
		break;
	case ASB_VIOLENTLY:
		rv = drbd_asb_recover_0p(peer_device);
		break;
	case ASB_DISCARD_SECONDARY:
		return resource->role[NOW] == R_PRIMARY ? SYNC_SOURCE_USE_BITMAP : SYNC_TARGET_USE_BITMAP;
	case ASB_CALL_HELPER:
		strategy = drbd_asb_recover_0p(peer_device);
		if (strategy == SYNC_TARGET_USE_BITMAP && resource->role[NOW] == R_PRIMARY) {
			enum drbd_state_rv rv2;

			 /* drbd_change_state() does not sleep while in SS_IN_TRANSIENT_STATE,
			  * we might be here in L_OFF which is transient.
			  * we do not need to wait for the after state change work either. */
			rv2 = change_role(resource, R_SECONDARY, CS_VERBOSE, false, NULL);
			if (rv2 != SS_SUCCESS) {
				drbd_maybe_khelper(device, connection, "pri-lost-after-sb");
			} else {
				drbd_warn(device, "Successfully gave up primary role.\n");
				rv = strategy;
			}
		} else
			rv = strategy;
	}

	return rv;
}

/**
 * drbd_asb_recover_2p  -  Recover after split-brain with two remaining primaries
 */
static enum sync_strategy drbd_asb_recover_2p(struct drbd_peer_device *peer_device) __must_hold(local)
{
	struct drbd_device *device = peer_device->device;
	struct drbd_connection *connection = peer_device->connection;
	enum sync_strategy strategy, rv = SPLIT_BRAIN_DISCONNECT;
	enum drbd_after_sb_p after_sb_2p;

	rcu_read_lock();
	after_sb_2p = rcu_dereference(connection->transport.net_conf)->after_sb_2p;
	rcu_read_unlock();
	switch (after_sb_2p) {
	case ASB_DISCARD_YOUNGER_PRI:
	case ASB_DISCARD_OLDER_PRI:
	case ASB_DISCARD_LEAST_CHG:
	case ASB_DISCARD_LOCAL:
	case ASB_DISCARD_REMOTE:
	case ASB_CONSENSUS:
	case ASB_DISCARD_SECONDARY:
	case ASB_DISCARD_ZERO_CHG:
	case ASB_RETRY_CONNECT:
		drbd_err(device, "Configuration error.\n");
		break;
	case ASB_VIOLENTLY:
		rv = drbd_asb_recover_0p(peer_device);
		break;
	case ASB_DISCONNECT:
		break;
	case ASB_CALL_HELPER:
		strategy = drbd_asb_recover_0p(peer_device);
		if (strategy == SYNC_TARGET_USE_BITMAP) {
			enum drbd_state_rv rv2;

			 /* drbd_change_state() does not sleep while in SS_IN_TRANSIENT_STATE,
			  * we might be here in L_OFF which is transient.
			  * we do not need to wait for the after state change work either. */
			rv2 = change_role(device->resource, R_SECONDARY, CS_VERBOSE, false, NULL);
			if (rv2 != SS_SUCCESS) {
				drbd_maybe_khelper(device, connection, "pri-lost-after-sb");
			} else {
				drbd_warn(device, "Successfully gave up primary role.\n");
				rv = strategy;
			}
		} else
			rv = strategy;
	}

	return rv;
}

static void drbd_uuid_dump_self(struct drbd_peer_device *peer_device, u64 bits, u64 flags)
{
	struct drbd_device *device = peer_device->device;

	drbd_info(peer_device, "self %016llX:%016llX:%016llX:%016llX bits:%llu flags:%llX\n",
		  (unsigned long long)drbd_resolved_uuid(peer_device, NULL),
		  (unsigned long long)drbd_bitmap_uuid(peer_device),
		  (unsigned long long)drbd_history_uuid(device, 0),
		  (unsigned long long)drbd_history_uuid(device, 1),
		  (unsigned long long)bits,
		  (unsigned long long)flags);
}


static void drbd_uuid_dump_peer(struct drbd_peer_device *peer_device, u64 bits, u64 flags)
{
	const int node_id = peer_device->device->resource->res_opts.node_id;

	drbd_info(peer_device, "peer %016llX:%016llX:%016llX:%016llX bits:%llu flags:%llX\n",
	     (unsigned long long)peer_device->current_uuid,
	     (unsigned long long)peer_device->bitmap_uuids[node_id],
	     (unsigned long long)peer_device->history_uuids[0],
	     (unsigned long long)peer_device->history_uuids[1],
	     (unsigned long long)bits,
	     (unsigned long long)flags);
}

static enum sync_strategy uuid_fixup_resync_end(struct drbd_peer_device *peer_device, int *rule_nr) __must_hold(local)
{
	struct drbd_device *device = peer_device->device;
	const int node_id = device->resource->res_opts.node_id;

	if (peer_device->bitmap_uuids[node_id] == (u64)0 && drbd_bitmap_uuid(peer_device) != (u64)0) {

		if (peer_device->connection->agreed_pro_version < 91)
			return REQUIRES_PROTO_91;

		if ((drbd_bitmap_uuid(peer_device) & ~UUID_PRIMARY) ==
		    (peer_device->history_uuids[0] & ~UUID_PRIMARY) &&
		    (drbd_history_uuid(device, 0) & ~UUID_PRIMARY) ==
		    (peer_device->history_uuids[0] & ~UUID_PRIMARY)) {
			struct drbd_peer_md *peer_md = &device->ldev->md.peers[peer_device->node_id];

			drbd_info(device, "was SyncSource, missed the resync finished event, corrected myself:\n");
			_drbd_uuid_push_history(device, peer_md->bitmap_uuid);
			peer_md->bitmap_uuid = 0;

			drbd_uuid_dump_self(peer_device,
					    device->disk_state[NOW] >= D_NEGOTIATING ? drbd_bm_total_weight(peer_device) : 0, 0);
			*rule_nr = 34;
		} else {
			drbd_info(device, "was SyncSource (peer failed to write sync_uuid)\n");
			*rule_nr = 36;
		}

		return SYNC_SOURCE_USE_BITMAP;
	}

	if (drbd_bitmap_uuid(peer_device) == (u64)0 && peer_device->bitmap_uuids[node_id] != (u64)0) {

		if (peer_device->connection->agreed_pro_version < 91)
			return REQUIRES_PROTO_91;

		if ((drbd_history_uuid(device, 0) & ~UUID_PRIMARY) ==
		    (peer_device->bitmap_uuids[node_id] & ~UUID_PRIMARY) &&
		    (drbd_history_uuid(device, 1) & ~UUID_PRIMARY) ==
		    (peer_device->history_uuids[0] & ~UUID_PRIMARY)) {
			int i;

			drbd_info(device, "was SyncTarget, peer missed the resync finished event, corrected peer:\n");

			for (i = ARRAY_SIZE(peer_device->history_uuids) - 1; i > 0; i--)
				peer_device->history_uuids[i] = peer_device->history_uuids[i - 1];
			peer_device->history_uuids[i] = peer_device->bitmap_uuids[node_id];
			peer_device->bitmap_uuids[node_id] = 0;

			drbd_uuid_dump_peer(peer_device, peer_device->dirty_bits, peer_device->uuid_flags);
			*rule_nr = 35;
		} else {
			drbd_info(device, "was SyncTarget (failed to write sync_uuid)\n");
			*rule_nr = 37;
		}

		return SYNC_TARGET_USE_BITMAP;
	}

	return UNDETERMINED;
}

static enum sync_strategy uuid_fixup_resync_start1(struct drbd_peer_device *peer_device, int *rule_nr) __must_hold(local)
{
	struct drbd_device *device = peer_device->device;
	const int node_id = peer_device->device->resource->res_opts.node_id;
	u64 self, peer;

	self = drbd_current_uuid(device) & ~UUID_PRIMARY;
	peer = peer_device->history_uuids[0] & ~UUID_PRIMARY;

	if (self == peer) {
		if (peer_device->connection->agreed_pro_version < 96 ?
		    (drbd_history_uuid(device, 0) & ~UUID_PRIMARY) ==
		    (peer_device->history_uuids[1] & ~UUID_PRIMARY) :
		    peer + UUID_NEW_BM_OFFSET == (peer_device->bitmap_uuids[node_id] & ~UUID_PRIMARY)) {
			int i;

			/* The last P_SYNC_UUID did not get though. Undo the last start of
			   resync as sync source modifications of the peer's UUIDs. */
			*rule_nr = 51;

			if (peer_device->connection->agreed_pro_version < 91)
				return REQUIRES_PROTO_91;

			peer_device->bitmap_uuids[node_id] = peer_device->history_uuids[0];
			for (i = 0; i < ARRAY_SIZE(peer_device->history_uuids) - 1; i++)
				peer_device->history_uuids[i] = peer_device->history_uuids[i + 1];
			peer_device->history_uuids[i] = 0;

			drbd_info(device, "Lost last syncUUID packet, corrected:\n");
			drbd_uuid_dump_peer(peer_device, peer_device->dirty_bits, peer_device->uuid_flags);

			return SYNC_TARGET_USE_BITMAP;
		}
	}

	return UNDETERMINED;
}

static enum sync_strategy uuid_fixup_resync_start2(struct drbd_peer_device *peer_device, int *rule_nr) __must_hold(local)
{
	struct drbd_device *device = peer_device->device;
	u64 self, peer;

	self = drbd_history_uuid(device, 0) & ~UUID_PRIMARY;
	peer = peer_device->current_uuid & ~UUID_PRIMARY;

	if (self == peer) {
		if (peer_device->connection->agreed_pro_version < 96 ?
		    (drbd_history_uuid(device, 1) & ~UUID_PRIMARY) ==
		    (peer_device->history_uuids[0] & ~UUID_PRIMARY) :
		    self + UUID_NEW_BM_OFFSET == (drbd_bitmap_uuid(peer_device) & ~UUID_PRIMARY)) {
			u64 bitmap_uuid;

			/* The last P_SYNC_UUID did not get though. Undo the last start of
			   resync as sync source modifications of our UUIDs. */
			*rule_nr = 71;

			if (peer_device->connection->agreed_pro_version < 91)
				return REQUIRES_PROTO_91;

			bitmap_uuid = _drbd_uuid_pull_history(peer_device);
			_drbd_uuid_set_bitmap(peer_device, bitmap_uuid);

			drbd_info(device, "Last syncUUID did not get through, corrected:\n");
			drbd_uuid_dump_self(peer_device,
					    device->disk_state[NOW] >= D_NEGOTIATING ? drbd_bm_total_weight(peer_device) : 0, 0);

			return SYNC_SOURCE_USE_BITMAP;
		}
	}

	return UNDETERMINED;
}

static enum sync_strategy drbd_uuid_compare(struct drbd_peer_device *peer_device,
			     int *rule_nr, int *peer_node_id) __must_hold(local)
{
	struct drbd_connection *connection = peer_device->connection;
	struct drbd_device *device = peer_device->device;
	const int node_id = device->resource->res_opts.node_id;
	u64 resolved_uuid;
	bool my_current_in_peers_history;
	bool peers_current_in_my_history;
	bool bitmap_matches_initial;
	bool flags_matches_initial;
	bool uuid_matches_initial;
	bool initial_handshake;
	u64 local_uuid_flags = 0;
	u64 self, peer;
	int i, j;

	resolved_uuid = drbd_resolved_uuid(peer_device, &local_uuid_flags) & ~UUID_PRIMARY;

	self = resolved_uuid;
	peer = peer_device->current_uuid & ~UUID_PRIMARY;
	local_uuid_flags |= drbd_collect_local_uuid_flags(peer_device, NULL);

	if (connection->agreed_pro_version < 110)
		local_uuid_flags &= UUID_FLAG_MASK_COMPAT_84;

	initial_handshake =
		test_bit(INITIAL_STATE_SENT, &peer_device->flags) &&
		!test_bit(INITIAL_STATE_RECEIVED, &peer_device->flags);
	uuid_matches_initial = self == (peer_device->comm_current_uuid & ~UUID_PRIMARY);
	bitmap_matches_initial = drbd_bitmap_uuid(peer_device) == peer_device->comm_bitmap_uuid;
	flags_matches_initial = local_uuid_flags == peer_device->comm_uuid_flags;
	if (initial_handshake && (!uuid_matches_initial || !flags_matches_initial || !bitmap_matches_initial)) {
		*rule_nr = 9;
		if (!uuid_matches_initial)
			drbd_warn(peer_device, "My current UUID changed during "
				  "handshake. Retry connecting.\n");
		if (!bitmap_matches_initial)
			drbd_warn(peer_device, "My bitmap UUID changed during "
				  "handshake. Retry connecting. 0x%llX to 0x%llX\n",
				  (unsigned long long)peer_device->comm_bitmap_uuid,
				  (unsigned long long)drbd_bitmap_uuid(peer_device));
		if (!flags_matches_initial)
			drbd_warn(peer_device, "My uuid_flags changed from 0x%llX to 0x%llX during "
				  "handshake. Retry connecting.\n",
				  (unsigned long long)peer_device->comm_uuid_flags,
				  (unsigned long long)local_uuid_flags);
		return RETRY_CONNECT;
	}

	/* Before DRBD 8.0.2 (from 2007), the uuid on sync targets was set to
	 * zero during resyncs for no good reason. */
	if (self == 0)
		self = UUID_JUST_CREATED;
	if (peer == 0)
		peer = UUID_JUST_CREATED;

	*rule_nr = 10;
	if (self == UUID_JUST_CREATED && peer == UUID_JUST_CREATED)
		return NO_SYNC;

	*rule_nr = 20;
	if (self == UUID_JUST_CREATED)
		return SYNC_TARGET_SET_BITMAP;

	*rule_nr = 30;
	if (peer == UUID_JUST_CREATED)
		return SYNC_SOURCE_SET_BITMAP;

	if (self == peer) {
		if (connection->agreed_pro_version < 110) {
			enum sync_strategy rv = uuid_fixup_resync_end(peer_device, rule_nr);
			if (rv != UNDETERMINED)
				return rv;
		}

		if (test_bit(RS_SOURCE_MISSED_END, &peer_device->flags)) {
			*rule_nr = 34;
			return SYNC_SOURCE_USE_BITMAP;
		}
		if (test_bit(RS_PEER_MISSED_END, &peer_device->flags)) {
			*rule_nr = 35;
			return SYNC_TARGET_USE_BITMAP;
		}

		*rule_nr = 39;
		if (peer_device->uuid_flags & UUID_FLAG_PRIMARY_LOST_QUORUM &&
		    !test_bit(PRIMARY_LOST_QUORUM, &device->flags))
			return SYNC_TARGET_IF_BOTH_FAILED;

		if (!(peer_device->uuid_flags & UUID_FLAG_PRIMARY_LOST_QUORUM) &&
		    test_bit(PRIMARY_LOST_QUORUM, &device->flags))
			return SYNC_SOURCE_IF_BOTH_FAILED;

		if (peer_device->uuid_flags & UUID_FLAG_PRIMARY_LOST_QUORUM &&
		    test_bit(PRIMARY_LOST_QUORUM, &device->flags))
			return test_bit(RESOLVE_CONFLICTS, &connection->transport.flags) ?
				SYNC_SOURCE_IF_BOTH_FAILED :
				SYNC_TARGET_IF_BOTH_FAILED;

		*rule_nr = 38;
		/* This is a safety net for the following two clauses */
		if (peer_device->uuid_flags & UUID_FLAG_RECONNECT &&
		    local_uuid_flags & UUID_FLAG_RECONNECT)
			return NO_SYNC;

		/* Peer crashed as primary, I survived, resync from me */
		if (peer_device->uuid_flags & UUID_FLAG_CRASHED_PRIMARY &&
		    local_uuid_flags & UUID_FLAG_RECONNECT)
			return SYNC_SOURCE_IF_BOTH_FAILED;

		/* I am a crashed primary, peer survived, resync to me */
		if (local_uuid_flags & UUID_FLAG_CRASHED_PRIMARY &&
		    peer_device->uuid_flags & UUID_FLAG_RECONNECT)
			return SYNC_TARGET_IF_BOTH_FAILED;

		/* One of us had a connection to the other node before.
		   i.e. this is not a common power failure. */
		if (peer_device->uuid_flags & UUID_FLAG_RECONNECT ||
		    local_uuid_flags & UUID_FLAG_RECONNECT)
			return NO_SYNC;

		/* Common power [off|failure]? */
		*rule_nr = 40;
		if (local_uuid_flags & UUID_FLAG_CRASHED_PRIMARY) {
			if ((peer_device->uuid_flags & UUID_FLAG_CRASHED_PRIMARY) &&
			    test_bit(RESOLVE_CONFLICTS, &connection->transport.flags))
				return SYNC_TARGET_IF_BOTH_FAILED;
			return SYNC_SOURCE_IF_BOTH_FAILED;
		} else if (peer_device->uuid_flags & UUID_FLAG_CRASHED_PRIMARY)
				return SYNC_TARGET_IF_BOTH_FAILED;
		else
			return NO_SYNC;
	}

	*rule_nr = 50;
	peer = peer_device->bitmap_uuids[node_id] & ~UUID_PRIMARY;
	if (self == peer)
		return SYNC_TARGET_USE_BITMAP;

	*rule_nr = 52;
	for (i = 0; i < DRBD_PEERS_MAX; i++) {
		peer = peer_device->bitmap_uuids[i] & ~UUID_PRIMARY;
		if (self == peer) {
			*peer_node_id = i;
			return SYNC_TARGET_CLEAR_BITMAP;
		}
	}

	if (connection->agreed_pro_version < 110) {
		enum sync_strategy rv = uuid_fixup_resync_start1(peer_device, rule_nr);
		if (rv != UNDETERMINED)
			return rv;
	}

	*rule_nr = 70;
	self = drbd_bitmap_uuid(peer_device) & ~UUID_PRIMARY;
	peer = peer_device->current_uuid & ~UUID_PRIMARY;
	if (self == peer)
		return SYNC_SOURCE_USE_BITMAP;

	*rule_nr = 72;
	for (i = 0; i < DRBD_NODE_ID_MAX; i++) {
		if (i == peer_device->node_id)
			continue;
		if (i == device->ldev->md.node_id)
			continue;
		if (connection->agreed_pro_version < 116 &&
		    device->ldev->md.peers[i].bitmap_index == -1)
			continue;
		self = device->ldev->md.peers[i].bitmap_uuid & ~UUID_PRIMARY;
		if (self == peer) {
			*peer_node_id = i;
			return SYNC_SOURCE_COPY_BITMAP;
		}
	}

	my_current_in_peers_history = false;
	self = resolved_uuid;
	for (i = 0; i < ARRAY_SIZE(peer_device->history_uuids); i++) {
		peer = peer_device->history_uuids[i] & ~UUID_PRIMARY;
		if (self == peer) {
			my_current_in_peers_history = true;
			break;
		}
	}

	if (connection->agreed_pro_version < 110) {
		enum sync_strategy rv = uuid_fixup_resync_start2(peer_device, rule_nr);
		if (rv != UNDETERMINED)
			return rv;
	}

	peers_current_in_my_history = false;
	peer = peer_device->current_uuid & ~UUID_PRIMARY;
	for (i = 0; i < HISTORY_UUIDS; i++) {
		self = drbd_history_uuid(device, i) & ~UUID_PRIMARY;
		if (self == peer) {
			peers_current_in_my_history = true;
			break;
		}
	}

	if (my_current_in_peers_history && !peers_current_in_my_history) {
		*rule_nr = 60;
		return SYNC_TARGET_SET_BITMAP;
	}
	if (!my_current_in_peers_history && peers_current_in_my_history) {
		*rule_nr = 80;
		return SYNC_SOURCE_SET_BITMAP;
	}

	*rule_nr = 90;
	self = drbd_bitmap_uuid(peer_device) & ~UUID_PRIMARY;
	peer = peer_device->bitmap_uuids[node_id] & ~UUID_PRIMARY;
	if (self == peer && self != ((u64)0))
		return SPLIT_BRAIN_AUTO_RECOVER;

	*rule_nr = 100;
	for (i = 0; i < HISTORY_UUIDS; i++) {
		self = drbd_history_uuid(device, i) & ~UUID_PRIMARY;
		/* Don't conclude to have "data divergence" from a "common ancestor"
		 * if that common ancestor is just a not used yet slot in the history,
		 * which is still initialized to zero on both peers. */
		if (self == 0)
			break;
		for (j = 0; j < ARRAY_SIZE(peer_device->history_uuids); j++) {
			peer = peer_device->history_uuids[j] & ~UUID_PRIMARY;
			if (peer == 0)
				break;
			if (self == peer)
				return SPLIT_BRAIN_DISCONNECT;
		}
	}

	return UNRELATED_DATA;
}

static void log_handshake(struct drbd_peer_device *peer_device)
{
	u64 uuid_flags = drbd_collect_local_uuid_flags(peer_device, NULL);

	drbd_info(peer_device, "drbd_sync_handshake:\n");
	drbd_uuid_dump_self(peer_device, peer_device->comm_bm_set, uuid_flags);
	drbd_uuid_dump_peer(peer_device, peer_device->dirty_bits, peer_device->uuid_flags);
}

static enum sync_strategy drbd_handshake(struct drbd_peer_device *peer_device,
			  int *rule_nr,
			  int *peer_node_id,
			  bool always_verbose) __must_hold(local)
{
	struct drbd_device *device = peer_device->device;
	enum sync_strategy strategy;

	spin_lock_irq(&device->ldev->md.uuid_lock);
	if (always_verbose)
		log_handshake(peer_device);

	strategy = drbd_uuid_compare(peer_device, rule_nr, peer_node_id);
	if (strategy != NO_SYNC && !always_verbose)
		log_handshake(peer_device);
	spin_unlock_irq(&device->ldev->md.uuid_lock);

	if (strategy != NO_SYNC || always_verbose)
		drbd_info(peer_device, "uuid_compare()=%s by rule %d\n", strategy_descriptor(strategy).name, *rule_nr);

	return strategy;
}

static bool is_resync_running(struct drbd_device *device)
{
	struct drbd_peer_device *peer_device;
	bool rv = false;

	rcu_read_lock();
	for_each_peer_device_rcu(peer_device, device) {
		enum drbd_repl_state repl_state = peer_device->repl_state[NOW];
		if (repl_state == L_SYNC_TARGET || repl_state == L_PAUSED_SYNC_T) {
			rv = true;
			break;
		}
	}
	rcu_read_unlock();

	return rv;
}

static int bitmap_mod_after_handshake(struct drbd_peer_device *peer_device, enum sync_strategy strategy, int peer_node_id)
{
	struct drbd_device *device = peer_device->device;

	/* reduce contention by giving up uuid_sem before taking bitmap locks */
	if (test_and_clear_bit(HOLDING_UUID_READ_LOCK, &peer_device->flags)) {
		struct drbd_transport *transport = &peer_device->connection->transport;
		up_read_non_owner(&device->uuid_sem);
		transport->ops->set_rcvtimeo(transport, DATA_STREAM, MAX_SCHEDULE_TIMEOUT);
	}

	if (strategy == SYNC_SOURCE_COPY_BITMAP) {
		int from = device->ldev->md.peers[peer_node_id].bitmap_index;

		if (from == -1)
			from = drbd_unallocated_index(device->ldev, device->bitmap->bm_max_peers);

		if (peer_device->bitmap_index == -1)
			return 0;

		if (from == -1)
			drbd_info(peer_device,
				  "Setting all bitmap bits, day0 bm not available node_id=%d\n",
				  peer_node_id);
		else
			drbd_info(peer_device,
				  "Copying bitmap of peer node_id=%d (bitmap_index=%d)\n",
				  peer_node_id, from);

		drbd_suspend_io(device, WRITE_ONLY);
		drbd_bm_slot_lock(peer_device, "copy_slot/set_many sync_handshake", BM_LOCK_BULK);
		if (from == -1)
			drbd_bm_set_many_bits(peer_device, 0, -1UL);
		else
			drbd_bm_copy_slot(device, from, peer_device->bitmap_index);
		drbd_bm_write(device, NULL);
		drbd_bm_slot_unlock(peer_device);
		drbd_resume_io(device);
	} else if (strategy == SYNC_TARGET_CLEAR_BITMAP) {
		drbd_info(peer_device, "Resync source provides bitmap (node_id=%d)\n", peer_node_id);
		drbd_suspend_io(device, WRITE_ONLY);
		drbd_bm_slot_lock(peer_device, "bm_clear_many_bits sync_handshake", BM_LOCK_BULK);
		drbd_bm_clear_many_bits(peer_device, 0, -1UL);
		drbd_bm_write(device, NULL);
		drbd_bm_slot_unlock(peer_device);
		drbd_resume_io(device);
	} else if (strategy == SYNC_SOURCE_SET_BITMAP || strategy == SYNC_TARGET_SET_BITMAP) {
		int (*io_func)(struct drbd_device *, struct drbd_peer_device *);
		int err;

		if (strategy == SYNC_TARGET_SET_BITMAP &&
		    drbd_current_uuid(device) == UUID_JUST_CREATED &&
		    is_resync_running(device))
			return 0;

		if (drbd_current_uuid(device) == UUID_JUST_CREATED) {
			drbd_info(peer_device, "Setting and writing the whole bitmap, fresh node\n");
			io_func = &drbd_bmio_set_allocated_n_write;
		} else {
			drbd_info(peer_device, "Setting and writing one bitmap slot, after drbd_sync_handshake\n");
			io_func = &drbd_bmio_set_n_write;
		}
		err = drbd_bitmap_io(device, io_func, "set_n_write sync_handshake",
				     BM_LOCK_CLEAR | BM_LOCK_BULK, peer_device);
		if (err)
			return -1;
	}
	return 0;
}

static enum drbd_repl_state strategy_to_repl_state(struct drbd_peer_device *peer_device,
						   enum drbd_role peer_role,
						   enum sync_strategy strategy)
{
	struct drbd_device *device = peer_device->device;
	enum drbd_role role = peer_device->device->resource->role[NOW];
	enum drbd_repl_state rv;

	if (strategy == SYNC_SOURCE_IF_BOTH_FAILED || strategy == SYNC_TARGET_IF_BOTH_FAILED) {
		if (role == R_PRIMARY || peer_role == R_PRIMARY) {
			/* We have at least one primary, follow that with the resync decision */
			rv = peer_role == R_SECONDARY ? L_WF_BITMAP_S :
				role == R_SECONDARY ? L_WF_BITMAP_T :
				L_ESTABLISHED;
			return rv;
		}
		/* No current primary. Handle it as a common power failure, consider the
		   roles at crash time */
	}

	if (strategy_descriptor(strategy).is_sync_source) {
		rv = L_WF_BITMAP_S;
	} else if (strategy_descriptor(strategy).is_sync_target) {
		rv = L_WF_BITMAP_T;
	} else {
		u64 peer_current_uuid = peer_device->current_uuid & ~UUID_PRIMARY;
		u64 my_current_uuid = drbd_current_uuid(device) & ~UUID_PRIMARY;

		rv = L_ESTABLISHED;
		if (peer_current_uuid == my_current_uuid && !(peer_device->uuid_flags & UUID_FLAG_SYNC_TARGET)) {
			if (drbd_bitmap_uuid(peer_device)) {
				drbd_info(peer_device, "clearing bitmap UUID and bitmap content (%lu bits)\n",
					  drbd_bm_total_weight(peer_device));
				down_write(&device->uuid_sem);
				drbd_uuid_set_bitmap(peer_device, 0);
				up_write(&device->uuid_sem);

			} else if (drbd_bm_total_weight(peer_device)) {
				drbd_info(peer_device, "bitmap content (%lu bits)\n",
					  drbd_bm_total_weight(peer_device));
			}
			drbd_bm_clear_many_bits(peer_device, 0, -1UL);
		}
	}

	return rv;
}

static void disk_states_to_strategy(struct drbd_peer_device *peer_device,
				    enum drbd_disk_state peer_disk_state,
				    enum sync_strategy *strategy, int rule_nr)
{
	enum drbd_disk_state disk_state = peer_device->comm_state.disk;
	struct drbd_device *device = peer_device->device;
	bool decide_based_on_dstates = false;
	bool prefer_local, either_inconsistent;

	if (disk_state == D_NEGOTIATING)
		disk_state = disk_state_from_md(device);

	either_inconsistent =
		(disk_state == D_INCONSISTENT && peer_disk_state > D_INCONSISTENT) ||
		(peer_disk_state == D_INCONSISTENT && disk_state > D_INCONSISTENT);

	if (peer_device->connection->agreed_pro_version >= 119) {
		bool dstates_want_resync =
			disk_state != peer_disk_state && disk_state >= D_INCONSISTENT &&
			peer_disk_state >= D_INCONSISTENT && peer_disk_state != D_UNKNOWN;
		bool resync_direction_arbitrary =
			*strategy == SYNC_TARGET_IF_BOTH_FAILED ||
			*strategy == SYNC_SOURCE_IF_BOTH_FAILED;

		decide_based_on_dstates =
			dstates_want_resync &&
			(((rule_nr == 38 || rule_nr == 39 || rule_nr == 40) &&
			  resync_direction_arbitrary) ||
			 (*strategy == NO_SYNC && either_inconsistent));

		prefer_local = disk_state > peer_disk_state;
		/* rule_nr 40 means that the current UUIDs are equal. The decision
		   was found by looking at the crashed_primary bits.
		   The current disk states might give a better basis for decision-making! */

		/* rule_nr 39 means that the current UUIDs are equal. The resync direction
		   was found by looking if a node lost quorum while being primary */
	} else {
		decide_based_on_dstates =
			(rule_nr == 40 || *strategy == NO_SYNC) && either_inconsistent;

		prefer_local = disk_state > D_INCONSISTENT;
	}

	if (decide_based_on_dstates) {
		*strategy = prefer_local ? SYNC_SOURCE_USE_BITMAP : SYNC_TARGET_USE_BITMAP;
		drbd_info(peer_device, "Becoming sync %s due to disk states. (%s/%s)\n",
			  strategy_descriptor(*strategy).is_sync_source ? "source" : "target",
			  drbd_disk_str(disk_state), drbd_disk_str(peer_disk_state));
	}
}

static enum drbd_repl_state drbd_attach_handshake(struct drbd_peer_device *peer_device,
						  enum drbd_disk_state peer_disk_state) __must_hold(local)
{
	enum sync_strategy strategy;
	int rule_nr, peer_node_id;

	strategy = drbd_handshake(peer_device, &rule_nr, &peer_node_id, true);

	if (!is_strategy_determined(strategy))
		return -1;

	bitmap_mod_after_handshake(peer_device, strategy, peer_node_id);
	disk_states_to_strategy(peer_device, peer_disk_state, &strategy, rule_nr);

	return strategy_to_repl_state(peer_device, peer_device->connection->peer_role[NOW], strategy);
}

/* drbd_sync_handshake() returns the new replication state on success, and -1
 * on failure.
 */
static enum drbd_repl_state drbd_sync_handshake(struct drbd_peer_device *peer_device,
						union drbd_state peer_state) __must_hold(local)
{
	struct drbd_device *device = peer_device->device;
	struct drbd_connection *connection = peer_device->connection;
	enum drbd_disk_state disk_state;
	struct net_conf *nc;
	enum sync_strategy strategy;
	int rule_nr, rr_conflict, always_asbp, peer_node_id = 0, r;
	enum drbd_role peer_role = peer_state.role;
	enum drbd_disk_state peer_disk_state = peer_state.disk;
	int required_protocol;

	strategy = drbd_handshake(peer_device, &rule_nr, &peer_node_id, true);

	disk_state = device->disk_state[NOW];
	if (disk_state == D_NEGOTIATING)
		disk_state = disk_state_from_md(device);

	if (strategy == RETRY_CONNECT)
		return -1; /* retry connect */

	if (strategy == UNRELATED_DATA) {
		drbd_alert(device, "Unrelated data, aborting!\n");
		return -2;
	}
	required_protocol = strategy_descriptor(strategy).required_protocol;
	if (required_protocol) {
		drbd_alert(device, "To resolve this both sides have to support at least protocol %d\n", required_protocol);
		return -2;
	}

	disk_states_to_strategy(peer_device, peer_disk_state, &strategy, rule_nr);

	if (strategy == SPLIT_BRAIN_AUTO_RECOVER && (!drbd_device_stable(device, NULL) || !(peer_device->uuid_flags & UUID_FLAG_STABLE))) {
		drbd_warn(device, "Ignore Split-Brain, for now, at least one side unstable\n");
		strategy = NO_SYNC;
	}

	if (strategy_descriptor(strategy).is_split_brain)
		drbd_maybe_khelper(device, connection, "initial-split-brain");

	rcu_read_lock();
	nc = rcu_dereference(connection->transport.net_conf);
	always_asbp = nc->always_asbp;
	rr_conflict = nc->rr_conflict;
	rcu_read_unlock();

	if (strategy == SPLIT_BRAIN_AUTO_RECOVER || (strategy == SPLIT_BRAIN_DISCONNECT && always_asbp)) {
		int pcount = (device->resource->role[NOW] == R_PRIMARY)
			   + (peer_role == R_PRIMARY);
		int forced = (strategy == SPLIT_BRAIN_DISCONNECT);

		if (device->resource->res_opts.quorum != QOU_OFF &&
		    connection->agreed_pro_version >= 113) {
			if (device->have_quorum[NOW] && !peer_state.quorum)
				strategy = SYNC_SOURCE_USE_BITMAP;
			else if (!device->have_quorum[NOW] && peer_state.quorum)
				strategy = SYNC_TARGET_USE_BITMAP;
		}
		if (strategy_descriptor(strategy).is_split_brain) {
			switch (pcount) {
			case 0:
				strategy = drbd_asb_recover_0p(peer_device);
				break;
			case 1:
				strategy = drbd_asb_recover_1p(peer_device);
				break;
			case 2:
				strategy = drbd_asb_recover_2p(peer_device);
				break;
			}
		}
		if (!strategy_descriptor(strategy).is_split_brain) {
			drbd_warn(device, "Split-Brain detected, %d primaries, "
			     "automatically solved. Sync from %s node\n",
			     pcount, strategy_descriptor(strategy).is_sync_target ? "peer" : "this");
			if (forced) {
				if (!strategy_descriptor(strategy).full_sync_equivalent) {
					drbd_alert(device, "Want full sync but cannot decide direction, dropping connection!\n");
					return -2;
				}
				drbd_warn(device, "Doing a full sync, since"
				     " UUIDs where ambiguous.\n");
				strategy = strategy_descriptor(strategy).full_sync_equivalent;
			}
		}
	}

	if (strategy == SPLIT_BRAIN_DISCONNECT) {
		if (test_bit(DISCARD_MY_DATA, &peer_device->flags) &&
		    !(peer_device->uuid_flags & UUID_FLAG_DISCARD_MY_DATA))
			strategy = SYNC_TARGET_USE_BITMAP;
		if (!test_bit(DISCARD_MY_DATA, &peer_device->flags) &&
		    (peer_device->uuid_flags & UUID_FLAG_DISCARD_MY_DATA))
			strategy = SYNC_SOURCE_USE_BITMAP;

		if (!strategy_descriptor(strategy).is_split_brain)
			drbd_warn(device, "Split-Brain detected, manually solved. "
			     "Sync from %s node\n",
			     strategy_descriptor(strategy).is_sync_target ? "peer" : "this");
	}

	if (strategy_descriptor(strategy).is_split_brain) {
		drbd_alert(device, "Split-Brain detected but unresolved, dropping connection!\n");
		drbd_maybe_khelper(device, connection, "split-brain");
		return -2;
	}

	if (!is_strategy_determined(strategy)) {
		drbd_alert(device, "Failed to fully determine sync strategy, dropping connection!\n");
		return -2;
	}

	if (strategy_descriptor(strategy).is_sync_target &&
	    strategy != SYNC_TARGET_IF_BOTH_FAILED &&
	    device->resource->role[NOW] == R_PRIMARY && device->disk_state[NOW] >= D_CONSISTENT) {
		switch (rr_conflict) {
		case ASB_CALL_HELPER:
			drbd_maybe_khelper(device, connection, "pri-lost");
			fallthrough;
		case ASB_DISCONNECT:
		case ASB_RETRY_CONNECT:
			drbd_err(device, "I shall become SyncTarget, but I am primary!\n");
			return rr_conflict == ASB_RETRY_CONNECT ? -1 : -2;
		case ASB_VIOLENTLY:
			drbd_warn(device, "Becoming SyncTarget, violating the stable-data"
			     "assumption\n");
		}
	}

	if (test_bit(CONN_DRY_RUN, &connection->flags)) {
		if (strategy == NO_SYNC)
			drbd_info(device, "dry-run connect: No resync, would become Connected immediately.\n");
		else
			drbd_info(device, "dry-run connect: Would become %s, doing a %s resync.",
				 drbd_repl_str(strategy_descriptor(strategy).is_sync_target ? L_SYNC_TARGET : L_SYNC_SOURCE),
				 strategy_descriptor(strategy).name);
		return -2;
	}

	r = bitmap_mod_after_handshake(peer_device, strategy, peer_node_id);
	if (r)
		return r;

	return strategy_to_repl_state(peer_device, peer_role, strategy);
}

static enum drbd_after_sb_p convert_after_sb(enum drbd_after_sb_p peer)
{
	/* ASB_DISCARD_REMOTE - ASB_DISCARD_LOCAL is valid */
	if (peer == ASB_DISCARD_REMOTE)
		return ASB_DISCARD_LOCAL;

	/* any other things with ASB_DISCARD_REMOTE or ASB_DISCARD_LOCAL are invalid */
	if (peer == ASB_DISCARD_LOCAL)
		return ASB_DISCARD_REMOTE;

	/* everything else is valid if they are equal on both sides. */
	return peer;
}

static int receive_protocol(struct drbd_connection *connection, struct packet_info *pi)
{
	struct p_protocol *p = pi->data;
	enum drbd_after_sb_p p_after_sb_0p, p_after_sb_1p, p_after_sb_2p;
	int p_proto, p_discard_my_data, p_two_primaries, cf;
	struct net_conf *nc, *old_net_conf, *new_net_conf = NULL;
	char integrity_alg[SHARED_SECRET_MAX] = "";
	struct crypto_shash *peer_integrity_tfm = NULL;
	void *int_dig_in = NULL, *int_dig_vv = NULL;

	p_proto		= be32_to_cpu(p->protocol);
	p_after_sb_0p	= be32_to_cpu(p->after_sb_0p);
	p_after_sb_1p	= be32_to_cpu(p->after_sb_1p);
	p_after_sb_2p	= be32_to_cpu(p->after_sb_2p);
	p_two_primaries = be32_to_cpu(p->two_primaries);
	cf		= be32_to_cpu(p->conn_flags);
	p_discard_my_data = cf & CF_DISCARD_MY_DATA;

	if (connection->agreed_pro_version >= 87) {
		int err;

		if (pi->size > sizeof(integrity_alg))
			return -EIO;
		err = drbd_recv_into(connection, integrity_alg, pi->size);
		if (err)
			return err;
		integrity_alg[SHARED_SECRET_MAX - 1] = 0;
	}

	if (pi->cmd != P_PROTOCOL_UPDATE) {
		if (cf & CF_DRY_RUN)
			set_bit(CONN_DRY_RUN, &connection->flags);

		rcu_read_lock();
		nc = rcu_dereference(connection->transport.net_conf);

		if (p_proto != nc->wire_protocol) {
			drbd_err(connection, "incompatible %s settings\n", "protocol");
			goto disconnect_rcu_unlock;
		}

		if (convert_after_sb(p_after_sb_0p) != nc->after_sb_0p) {
			drbd_err(connection, "incompatible %s settings\n", "after-sb-0pri");
			goto disconnect_rcu_unlock;
		}

		if (convert_after_sb(p_after_sb_1p) != nc->after_sb_1p) {
			drbd_err(connection, "incompatible %s settings\n", "after-sb-1pri");
			goto disconnect_rcu_unlock;
		}

		if (convert_after_sb(p_after_sb_2p) != nc->after_sb_2p) {
			drbd_err(connection, "incompatible %s settings\n", "after-sb-2pri");
			goto disconnect_rcu_unlock;
		}

		if (p_discard_my_data && test_bit(CONN_DISCARD_MY_DATA, &connection->flags)) {
			drbd_err(connection, "incompatible %s settings\n", "discard-my-data");
			goto disconnect_rcu_unlock;
		}

		if (p_two_primaries != nc->two_primaries) {
			drbd_err(connection, "incompatible %s settings\n", "allow-two-primaries");
			goto disconnect_rcu_unlock;
		}

		if (strcmp(integrity_alg, nc->integrity_alg)) {
			drbd_err(connection, "incompatible %s settings\n", "data-integrity-alg");
			goto disconnect_rcu_unlock;
		}

		rcu_read_unlock();
	}

	if (integrity_alg[0]) {
		int hash_size;

		/*
		 * We can only change the peer data integrity algorithm
		 * here.  Changing our own data integrity algorithm
		 * requires that we send a P_PROTOCOL_UPDATE packet at
		 * the same time; otherwise, the peer has no way to
		 * tell between which packets the algorithm should
		 * change.
		 */

		peer_integrity_tfm = crypto_alloc_shash(integrity_alg, 0, 0);
		if (IS_ERR(peer_integrity_tfm)) {
			peer_integrity_tfm = NULL;
			drbd_err(connection, "peer data-integrity-alg %s not supported\n",
				 integrity_alg);
			goto disconnect;
		}

		hash_size = crypto_shash_digestsize(peer_integrity_tfm);
		int_dig_in = kmalloc(hash_size, GFP_KERNEL);
		int_dig_vv = kmalloc(hash_size, GFP_KERNEL);
		if (!(int_dig_in && int_dig_vv)) {
			drbd_err(connection, "Allocation of buffers for data integrity checking failed\n");
			goto disconnect;
		}
	}

	new_net_conf = kmalloc(sizeof(struct net_conf), GFP_KERNEL);
	if (!new_net_conf) {
		drbd_err(connection, "Allocation of new net_conf failed\n");
		goto disconnect;
	}

	if (mutex_lock_interruptible(&connection->resource->conf_update)) {
		drbd_err(connection, "Interrupted while waiting for conf_update\n");
		goto disconnect;
	}

	mutex_lock(&connection->mutex[DATA_STREAM]);
	old_net_conf = connection->transport.net_conf;
	*new_net_conf = *old_net_conf;

	new_net_conf->wire_protocol = p_proto;
	new_net_conf->after_sb_0p = convert_after_sb(p_after_sb_0p);
	new_net_conf->after_sb_1p = convert_after_sb(p_after_sb_1p);
	new_net_conf->after_sb_2p = convert_after_sb(p_after_sb_2p);
	new_net_conf->two_primaries = p_two_primaries;

	rcu_assign_pointer(connection->transport.net_conf, new_net_conf);
	mutex_unlock(&connection->mutex[DATA_STREAM]);
	mutex_unlock(&connection->resource->conf_update);

	crypto_free_shash(connection->peer_integrity_tfm);
	kfree(connection->int_dig_in);
	kfree(connection->int_dig_vv);
	connection->peer_integrity_tfm = peer_integrity_tfm;
	connection->int_dig_in = int_dig_in;
	connection->int_dig_vv = int_dig_vv;

	if (strcmp(old_net_conf->integrity_alg, integrity_alg))
		drbd_info(connection, "peer data-integrity-alg: %s\n",
			  integrity_alg[0] ? integrity_alg : "(none)");

	synchronize_rcu();
	kfree(old_net_conf);
	return 0;

disconnect_rcu_unlock:
	rcu_read_unlock();
disconnect:
	kfree(new_net_conf);
	crypto_free_shash(peer_integrity_tfm);
	kfree(int_dig_in);
	kfree(int_dig_vv);
	change_cstate(connection, C_DISCONNECTING, CS_HARD);
	return -EIO;
}

/* helper function
 * input: alg name, feature name
 * return: NULL (alg name was "")
 *         ERR_PTR(error) if something goes wrong
 *         or the crypto hash ptr, if it worked out ok. */
static struct crypto_shash *drbd_crypto_alloc_digest_safe(const struct drbd_device *device,
		const char *alg, const char *name)
{
	struct crypto_shash *tfm;

	if (!alg[0])
		return NULL;

	tfm = crypto_alloc_shash(alg, 0, 0);
	if (IS_ERR(tfm)) {
		drbd_err(device, "Can not allocate \"%s\" as %s (reason: %ld)\n",
			alg, name, PTR_ERR(tfm));
		return tfm;
	}
	return tfm;
}

/*
 * config_unknown_volume  -  device configuration command for unknown volume
 *
 * When a device is added to an existing connection, the node on which the
 * device is added first will send configuration commands to its peer but the
 * peer will not know about the device yet.  It will warn and ignore these
 * commands.  Once the device is added on the second node, the second node will
 * send the same device configuration commands, but in the other direction.
 *
 * (We can also end up here if drbd is misconfigured.)
 */
static int config_unknown_volume(struct drbd_connection *connection, struct packet_info *pi)
{
	drbd_warn(connection, "%s packet received for volume %d, which is not configured locally\n",
		  drbd_packet_name(pi->cmd), pi->vnr);
	return ignore_remaining_packet(connection, pi->size);
}

static int receive_SyncParam(struct drbd_connection *connection, struct packet_info *pi)
{
	struct drbd_peer_device *peer_device;
	struct drbd_device *device;
	struct p_rs_param_95 *p;
	unsigned int header_size, data_size, exp_max_sz;
	struct crypto_shash *verify_tfm = NULL;
	struct crypto_shash *csums_tfm = NULL;
	struct net_conf *old_net_conf, *new_net_conf = NULL;
	struct peer_device_conf *old_peer_device_conf = NULL, *new_peer_device_conf = NULL;
	const int apv = connection->agreed_pro_version;
	struct fifo_buffer *old_plan = NULL, *new_plan = NULL;
	struct drbd_resource *resource = connection->resource;
	unsigned int fifo_size = 0;
	int err;

	peer_device = conn_peer_device(connection, pi->vnr);
	if (!peer_device)
		return config_unknown_volume(connection, pi);
	device = peer_device->device;

	exp_max_sz  = apv <= 87 ? sizeof(struct p_rs_param)
		    : apv == 88 ? sizeof(struct p_rs_param)
					+ SHARED_SECRET_MAX
		    : apv <= 94 ? sizeof(struct p_rs_param_89)
		    : /* apv >= 95 */ sizeof(struct p_rs_param_95);

	if (pi->size > exp_max_sz) {
		drbd_err(device, "SyncParam packet too long: received %u, expected <= %u bytes\n",
		    pi->size, exp_max_sz);
		return -EIO;
	}

	if (apv <= 88) {
		header_size = sizeof(struct p_rs_param);
		data_size = pi->size - header_size;
	} else if (apv <= 94) {
		header_size = sizeof(struct p_rs_param_89);
		data_size = pi->size - header_size;
		D_ASSERT(device, data_size == 0);
	} else {
		header_size = sizeof(struct p_rs_param_95);
		data_size = pi->size - header_size;
		D_ASSERT(device, data_size == 0);
	}

	err = drbd_recv_all(connection, (void **)&p, header_size + data_size);
	if (err)
		return err;

	err = mutex_lock_interruptible(&resource->conf_update);
	if (err) {
		drbd_err(connection, "Interrupted while waiting for conf_update\n");
		return err;
	}
	old_net_conf = connection->transport.net_conf;
	if (get_ldev(device)) {
		new_peer_device_conf = kzalloc(sizeof(struct peer_device_conf), GFP_KERNEL);
		if (!new_peer_device_conf) {
			put_ldev(device);
			mutex_unlock(&resource->conf_update);
			drbd_err(device, "Allocation of new peer_device_conf failed\n");
			return -ENOMEM;
		}
		/* With a non-zero new_peer_device_conf, we will call put_ldev() below.  */

		old_peer_device_conf = peer_device->conf;
		*new_peer_device_conf = *old_peer_device_conf;

		new_peer_device_conf->resync_rate = be32_to_cpu(p->resync_rate);
	}

	if (apv >= 88) {
		if (apv == 88) {
			if (data_size > SHARED_SECRET_MAX || data_size == 0) {
				drbd_err(device, "verify-alg too long, "
					 "peer wants %u, accepting only %u byte\n",
					 data_size, SHARED_SECRET_MAX);
				goto reconnect;
			}
			p->verify_alg[data_size] = 0;

		} else /* apv >= 89 */ {
			/* we still expect NUL terminated strings */
			/* but just in case someone tries to be evil */
			D_ASSERT(device, p->verify_alg[SHARED_SECRET_MAX-1] == 0);
			D_ASSERT(device, p->csums_alg[SHARED_SECRET_MAX-1] == 0);
			p->verify_alg[SHARED_SECRET_MAX-1] = 0;
			p->csums_alg[SHARED_SECRET_MAX-1] = 0;
		}

		if (strcmp(old_net_conf->verify_alg, p->verify_alg)) {
			if (peer_device->repl_state[NOW] == L_OFF) {
				drbd_err(device, "Different verify-alg settings. me=\"%s\" peer=\"%s\"\n",
				    old_net_conf->verify_alg, p->verify_alg);
				goto disconnect;
			}
			verify_tfm = drbd_crypto_alloc_digest_safe(device,
					p->verify_alg, "verify-alg");
			if (IS_ERR(verify_tfm)) {
				verify_tfm = NULL;
				goto disconnect;
			}
		}

		if (apv >= 89 && strcmp(old_net_conf->csums_alg, p->csums_alg)) {
			if (peer_device->repl_state[NOW] == L_OFF) {
				drbd_err(device, "Different csums-alg settings. me=\"%s\" peer=\"%s\"\n",
				    old_net_conf->csums_alg, p->csums_alg);
				goto disconnect;
			}
			csums_tfm = drbd_crypto_alloc_digest_safe(device,
					p->csums_alg, "csums-alg");
			if (IS_ERR(csums_tfm)) {
				csums_tfm = NULL;
				goto disconnect;
			}
		}

		if (apv > 94 && new_peer_device_conf) {
			new_peer_device_conf->c_plan_ahead = be32_to_cpu(p->c_plan_ahead);
			new_peer_device_conf->c_delay_target = be32_to_cpu(p->c_delay_target);
			new_peer_device_conf->c_fill_target = be32_to_cpu(p->c_fill_target);
			new_peer_device_conf->c_max_rate = be32_to_cpu(p->c_max_rate);

			fifo_size = (new_peer_device_conf->c_plan_ahead * 10 * RS_MAKE_REQS_INTV) / HZ;
			old_plan = rcu_dereference_protected(peer_device->rs_plan_s,
				lockdep_is_held(&resource->conf_update));
			if (!old_plan || fifo_size != old_plan->size) {
				new_plan = fifo_alloc(fifo_size);
				if (!new_plan) {
					drbd_err(device, "kmalloc of fifo_buffer failed");
					goto disconnect;
				}
			}
		}

		if (verify_tfm || csums_tfm) {
			new_net_conf = kzalloc(sizeof(struct net_conf), GFP_KERNEL);
			if (!new_net_conf) {
				drbd_err(device, "Allocation of new net_conf failed\n");
				goto disconnect;
			}

			*new_net_conf = *old_net_conf;

			if (verify_tfm) {
				strcpy(new_net_conf->verify_alg, p->verify_alg);
				new_net_conf->verify_alg_len = strlen(p->verify_alg) + 1;
				crypto_free_shash(connection->verify_tfm);
				connection->verify_tfm = verify_tfm;
				drbd_info(device, "using verify-alg: \"%s\"\n", p->verify_alg);
			}
			if (csums_tfm) {
				strcpy(new_net_conf->csums_alg, p->csums_alg);
				new_net_conf->csums_alg_len = strlen(p->csums_alg) + 1;
				crypto_free_shash(connection->csums_tfm);
				connection->csums_tfm = csums_tfm;
				drbd_info(device, "using csums-alg: \"%s\"\n", p->csums_alg);
			}
			rcu_assign_pointer(connection->transport.net_conf, new_net_conf);
		}
	}

	if (new_peer_device_conf) {
		rcu_assign_pointer(peer_device->conf, new_peer_device_conf);
		put_ldev(device);
	}

	if (new_plan)
		rcu_assign_pointer(peer_device->rs_plan_s, new_plan);

	mutex_unlock(&resource->conf_update);
	synchronize_rcu();
	if (new_net_conf)
		kfree(old_net_conf);
	kfree(old_peer_device_conf);
	if (new_plan)
		kfree(old_plan);

	return 0;

reconnect:
	if (new_peer_device_conf) {
		put_ldev(device);
		kfree(new_peer_device_conf);
	}
	mutex_unlock(&resource->conf_update);
	return -EIO;

disconnect:
	kfree(new_plan);
	if (new_peer_device_conf) {
		put_ldev(device);
		kfree(new_peer_device_conf);
	}
	mutex_unlock(&resource->conf_update);
	/* just for completeness: actually not needed,
	 * as this is not reached if csums_tfm was ok. */
	crypto_free_shash(csums_tfm);
	/* but free the verify_tfm again, if csums_tfm did not work out */
	crypto_free_shash(verify_tfm);
	change_cstate(connection, C_DISCONNECTING, CS_HARD);
	return -EIO;
}

static void drbd_setup_order_type(struct drbd_device *device, int peer)
{
	/* sorry, we currently have no working implementation
	 * of distributed TCQ */
}

/* warn if the arguments differ by more than 12.5% */
static void warn_if_differ_considerably(struct drbd_peer_device *peer_device,
	const char *s, sector_t a, sector_t b)
{
	sector_t d;
	if (a == 0 || b == 0)
		return;
	d = (a > b) ? (a - b) : (b - a);
	if (d > (a>>3) || d > (b>>3))
		drbd_warn(peer_device, "Considerable difference in %s: %llus vs. %llus\n", s,
		     (unsigned long long)a, (unsigned long long)b);
}

/* Maximum bio size that a protocol version supports. */
static unsigned int conn_max_bio_size(struct drbd_connection *connection)
{
	if (connection->agreed_pro_version >= 100)
		return DRBD_MAX_BIO_SIZE;
	else if (connection->agreed_pro_version >= 95)
		return DRBD_MAX_BIO_SIZE_P95;
	else
		return DRBD_MAX_SIZE_H80_PACKET;
}

static struct drbd_peer_device *get_neighbor_device(struct drbd_device *device,
		enum drbd_neighbor neighbor)
{
	s32 self_id, peer_id, pivot;
	struct drbd_peer_device *peer_device, *peer_device_ret = NULL;

	if (!get_ldev(device))
		return NULL;
	self_id = device->ldev->md.node_id;
	put_ldev(device);

	pivot = neighbor == NEXT_LOWER ? 0 : neighbor == NEXT_HIGHER ? S32_MAX : -1;
	if (pivot == -1)
		return NULL;

	rcu_read_lock();
	for_each_peer_device_rcu(peer_device, device) {
		bool found_new = false;
		peer_id = peer_device->node_id;

		if (neighbor == NEXT_LOWER && peer_id < self_id && peer_id >= pivot)
			found_new = true;
		else if (neighbor == NEXT_HIGHER && peer_id > self_id && peer_id <= pivot)
			found_new = true;

		if (found_new && peer_device->disk_state[NOW] >= D_INCONSISTENT) {
			pivot = peer_id;
			peer_device_ret = peer_device;
		}
	}
	rcu_read_unlock();

	return peer_device_ret;
}

static void maybe_trigger_resync(struct drbd_device *device, struct drbd_peer_device *peer_device, bool grew, bool skip)
{
	if (!peer_device)
		return;
	if (peer_device->repl_state[NOW] <= L_OFF)
		return;
	if (test_and_clear_bit(RESIZE_PENDING, &peer_device->flags) ||
	    (grew && peer_device->repl_state[NOW] == L_ESTABLISHED)) {
		if (peer_device->disk_state[NOW] >= D_INCONSISTENT &&
		    device->disk_state[NOW] >= D_INCONSISTENT) {
			if (skip)
				drbd_info(peer_device, "Resync of new storage suppressed with --assume-clean\n");
			else
				resync_after_online_grow(peer_device);
		} else
			set_bit(RESYNC_AFTER_NEG, &peer_device->flags);
	}
}

static int receive_sizes(struct drbd_connection *connection, struct packet_info *pi)
{
	struct drbd_peer_device *peer_device, *peer_device_it = NULL;
	struct drbd_device *device;
	struct p_sizes *p = pi->data;
	struct o_qlim *o = (connection->agreed_features & DRBD_FF_WSAME) ? p->qlim : NULL;
	uint64_t p_size, p_usize, p_csize;
	uint64_t my_usize, my_max_size, cur_size;
	enum determine_dev_size dd = DS_UNCHANGED;
	bool should_send_sizes = false;
	enum dds_flags ddsf;
	unsigned int protocol_max_bio_size;
	bool have_ldev = false;
	bool have_mutex = false;
	bool is_handshake;
	int err;
	u64 im;

	peer_device = conn_peer_device(connection, pi->vnr);
	if (!peer_device)
		return config_unknown_volume(connection, pi);
	device = peer_device->device;

	err = mutex_lock_interruptible(&connection->resource->conf_update);
	if (err) {
		drbd_err(connection, "Interrupted while waiting for conf_update\n");
		goto out;
	}
	have_mutex = true;

	/* just store the peer's disk size for now.
	 * we still need to figure out whether we accept that. */
	p_size = be64_to_cpu(p->d_size);
	p_usize = be64_to_cpu(p->u_size);
	p_csize = be64_to_cpu(p->c_size);

	peer_device->d_size = p_size;
	peer_device->u_size = p_usize;
	peer_device->c_size = p_csize;

	/* Ignore "current" size for calculating "max" size. */
	/* If it used to have a disk, but now is detached, don't revert back to zero. */
	if (p_size)
		peer_device->max_size = p_size;

	cur_size = get_capacity(device->vdisk);
	dynamic_drbd_dbg(device, "current_size: %llu\n", (unsigned long long)cur_size);
	dynamic_drbd_dbg(peer_device, "c_size: %llu u_size: %llu d_size: %llu max_size: %llu\n",
			(unsigned long long)p_csize,
			(unsigned long long)p_usize,
			(unsigned long long)p_size,
			(unsigned long long)peer_device->max_size);

	if ((p_size && p_csize > p_size) || (p_usize && p_csize > p_usize)) {
		drbd_warn(peer_device, "Peer sent bogus sizes, disconnecting\n");
		goto disconnect;
	}

	/* The protocol version limits how big requests can be.  In addition,
	 * peers before protocol version 94 cannot split large requests into
	 * multiple bios; their reported max_bio_size is a hard limit.
	 */
	protocol_max_bio_size = conn_max_bio_size(connection);
	peer_device->max_bio_size = min(be32_to_cpu(p->max_bio_size), protocol_max_bio_size);
	ddsf = be16_to_cpu(p->dds_flags);

	is_handshake = (peer_device->repl_state[NOW] == L_OFF);
	/* Maybe the peer knows something about peers I cannot currently see. */
	ddsf |= DDSF_IGNORE_PEER_CONSTRAINTS;

	set_bit(HAVE_SIZES, &peer_device->flags);

	if (get_ldev(device)) {
		sector_t new_size;

		have_ldev = true;

		rcu_read_lock();
		my_usize = rcu_dereference(device->ldev->disk_conf)->disk_size;
		rcu_read_unlock();

		my_max_size = drbd_get_max_capacity(device, device->ldev, false);
		dynamic_drbd_dbg(peer_device, "la_size: %llu my_usize: %llu my_max_size: %llu\n",
			(unsigned long long)device->ldev->md.effective_size,
			(unsigned long long)my_usize,
			(unsigned long long)my_max_size);

		if (peer_device->disk_state[NOW] > D_DISKLESS)
			warn_if_differ_considerably(peer_device, "lower level device sizes",
				   p_size, my_max_size);
		warn_if_differ_considerably(peer_device, "user requested size",
					    p_usize, my_usize);

		if (is_handshake)
			p_usize = min_not_zero(my_usize, p_usize);

		if (p_usize == 0) {
			/* Peer may reset usize to zero only if it has a backend.
			 * Because a diskless node has no disk config,
			 * and always sends zero. */
			if (p_size == 0)
				p_usize = my_usize;
		}

		new_size = drbd_new_dev_size(device, p_csize, p_usize, ddsf);

		/* Never shrink a device with usable data during connect,
		 * or "attach" on the peer.
		 * But allow online shrinking if we are connected. */
		if (new_size < cur_size &&
		    device->disk_state[NOW] >= D_OUTDATED &&
		    (peer_device->repl_state[NOW] < L_ESTABLISHED || peer_device->disk_state[NOW] == D_DISKLESS)) {
			drbd_err(peer_device, "The peer's disk size is too small! (%llu < %llu sectors)\n",
					(unsigned long long)new_size, (unsigned long long)cur_size);
			goto disconnect;
		}

		/* Disconnect, if we cannot grow to the peer's current size */
		if (my_max_size < p_csize && !is_handshake) {
			drbd_err(peer_device, "Peer's size larger than my maximum capacity (%llu < %llu sectors)\n",
					(unsigned long long)my_max_size, (unsigned long long)p_csize);
			goto disconnect;
		}

		if (my_usize != p_usize) {
			struct disk_conf *old_disk_conf, *new_disk_conf;

			new_disk_conf = kzalloc(sizeof(struct disk_conf), GFP_KERNEL);
			if (!new_disk_conf) {
				drbd_err(device, "Allocation of new disk_conf failed\n");
				err = -ENOMEM;
				goto out;
			}

			old_disk_conf = device->ldev->disk_conf;
			*new_disk_conf = *old_disk_conf;
			new_disk_conf->disk_size = p_usize;

			rcu_assign_pointer(device->ldev->disk_conf, new_disk_conf);
			synchronize_rcu();
			kfree(old_disk_conf);

			drbd_info(peer_device, "Peer sets u_size to %llu sectors (old: %llu)\n",
				 (unsigned long long)p_usize, (unsigned long long)my_usize);
			/* Do not set should_send_sizes here. That might cause packet storms */
		}
	}

	/* Leave drbd_reconsider_queue_parameters() before drbd_determine_dev_size().
	   In case we cleared the QUEUE_FLAG_DISCARD from our queue in
	   drbd_reconsider_queue_parameters(), we can be sure that after
	   drbd_determine_dev_size() no REQ_OP_DISCARDs are in the queue. */
	if (have_ldev) {
		enum dds_flags local_ddsf = ddsf;
		drbd_reconsider_queue_parameters(device, device->ldev, o);

		/* To support thinly provisioned nodes (partial resync) joining later,
		   clear all bitmap slots, including the unused ones. */
		if (device->ldev->md.effective_size == 0)
			local_ddsf |= DDSF_NO_RESYNC;

		dd = drbd_determine_dev_size(device, p_csize, local_ddsf, NULL);

		if (dd == DS_GREW || dd == DS_SHRUNK)
			should_send_sizes = true;

		if (dd == DS_ERROR) {
			err = -EIO;
			goto out;
		}
		drbd_md_sync_if_dirty(device);
	} else {
		uint64_t new_size = 0;

		drbd_reconsider_queue_parameters(device, NULL, o);
		/* In case I am diskless, need to accept the peer's *current* size.
		 *
		 * At this point, the peer knows more about my disk, or at
		 * least about what we last agreed upon, than myself.
		 * So if his c_size is less than his d_size, the most likely
		 * reason is that *my* d_size was smaller last time we checked,
		 * or some other peer does not (yet) have enough room.
		 *
		 * Unless of course he does not have a disk himself.
		 * In which case we ignore this completely.
		 */
		new_size = p_csize;
		new_size = min_not_zero(new_size, p_usize);
		new_size = min_not_zero(new_size, p_size);

		if (new_size == 0) {
			/* Ignore, peer does not know nothing. */
		} else if (new_size == cur_size) {
			/* nothing to do */
		} else if (cur_size != 0 && p_size == 0) {
			dynamic_drbd_dbg(peer_device,
					"Ignored diskless peer device size (peer:%llu != me:%llu sectors)!\n",
					(unsigned long long)new_size, (unsigned long long)cur_size);
		} else if (new_size < cur_size && device->resource->role[NOW] == R_PRIMARY) {
			drbd_err(peer_device,
				"The peer's device size is too small! (%llu < %llu sectors); demote me first!\n",
				(unsigned long long)new_size, (unsigned long long)cur_size);
			goto disconnect;

/* FIXME for each peer device: can I currently see any peer with attached disk
 * with a current size smaller than what that guy advertises? Then I better not
 * believe him.
 */
		} else {
			/* I believe the peer, if
			 *  - I don't have a current size myself
			 *  - we agree on the size anyways
			 *  - I do have a current size, am Secondary,
			 *    and he has the only disk
			 *  - I do have a current size, am Primary,
			 *    and he has the only disk,
			 *    which is larger than my current size
			 */
			should_send_sizes = true;
			drbd_set_my_capacity(device, new_size);
		}
	}

	if (device->device_conf.max_bio_size > protocol_max_bio_size ||
	    (connection->agreed_pro_version < 94 &&
	     device->device_conf.max_bio_size > peer_device->max_bio_size)) {
		drbd_err(device, "Peer cannot deal with requests bigger than %u. "
			 "Please reduce max_bio_size in the configuration.\n",
			 peer_device->max_bio_size);
		goto disconnect;
	}

	if (have_ldev) {
		if (device->ldev->known_size != drbd_get_capacity(device->ldev->backing_bdev)) {
			device->ldev->known_size = drbd_get_capacity(device->ldev->backing_bdev);
			should_send_sizes = true;
		}

		drbd_setup_order_type(device, be16_to_cpu(p->queue_order_type));
	}

	cur_size = get_capacity(device->vdisk);

	for_each_peer_device_ref(peer_device_it, im, device) {
		struct drbd_connection *con_it = peer_device_it->connection;

		/* drop cached max_size, if we already grew beyond it */
		if (peer_device_it->max_size < cur_size)
			peer_device_it->max_size = 0;

		if (con_it->cstate[NOW] < C_CONNECTED)
			continue;

		/* Send size updates only if something relevant has changed.
		 * TODO: only tell the sender thread to do so,
		 * or we may end up in a distributed deadlock on congestion. */

		if (should_send_sizes)
			drbd_send_sizes(peer_device_it, p_usize, ddsf);
	}

	maybe_trigger_resync(device, get_neighbor_device(device, NEXT_HIGHER),
					dd == DS_GREW, ddsf & DDSF_NO_RESYNC);
	maybe_trigger_resync(device, get_neighbor_device(device, NEXT_LOWER),
					dd == DS_GREW, ddsf & DDSF_NO_RESYNC);
	err = 0;

out:
	if (have_ldev)
		put_ldev(device);
	if (have_mutex)
		mutex_unlock(&connection->resource->conf_update);
	return err;

disconnect:
	/* don't let a rejected peer confuse future handshakes with different peers. */
	peer_device->max_size = 0;
	change_cstate(connection, C_DISCONNECTING, CS_HARD);
	err = -EIO;
	goto out;
}

static enum sync_strategy resolve_splitbrain_from_disk_states(struct drbd_peer_device *peer_device)
{
	struct drbd_device *device = peer_device->device;
	enum drbd_disk_state peer_disk_state = peer_device->disk_state[NOW];
	enum drbd_disk_state disk_state = device->disk_state[NOW];

	return  disk_state <= D_UP_TO_DATE && peer_disk_state == D_UP_TO_DATE ? SYNC_TARGET_USE_BITMAP :
		disk_state == D_UP_TO_DATE && peer_disk_state <= D_UP_TO_DATE ? SYNC_SOURCE_USE_BITMAP :
		SPLIT_BRAIN_AUTO_RECOVER;
}

static void drbd_resync(struct drbd_peer_device *peer_device,
			enum resync_reason reason) __must_hold(local)
{
	enum drbd_role peer_role = peer_device->connection->peer_role[NOW];
	enum drbd_repl_state new_repl_state;
	enum drbd_disk_state peer_disk_state;
	enum sync_strategy strategy;
	int rule_nr, peer_node_id;
	enum drbd_state_rv rv;

	strategy = drbd_handshake(peer_device, &rule_nr, &peer_node_id, reason == DISKLESS_PRIMARY);
	if (strategy == SPLIT_BRAIN_AUTO_RECOVER && reason == AFTER_UNSTABLE)
		strategy = resolve_splitbrain_from_disk_states(peer_device);

	if (!is_strategy_determined(strategy)) {
		drbd_info(peer_device, "Unexpected result of handshake() %s!\n", strategy_descriptor(strategy).name);
		return;
	}

	new_repl_state = strategy_to_repl_state(peer_device, peer_role, strategy);
	if (new_repl_state != L_ESTABLISHED) {
		bitmap_mod_after_handshake(peer_device, strategy, peer_node_id);
		drbd_info(peer_device, "Becoming %s %s\n", drbd_repl_str(new_repl_state),
			  reason == AFTER_UNSTABLE ? "after unstable" : "because primary is diskless");
	}

	peer_disk_state = peer_device->disk_state[NOW];
	if (new_repl_state == L_ESTABLISHED && peer_disk_state >= D_CONSISTENT &&
	    peer_device->device->disk_state[NOW] == D_OUTDATED) {
		/* No resync with up-to-date peer -> I should be consistent or up-to-date as well.
		   Note: Former unstable (but up-to-date) nodes become consistent for a short
		   time after loosing their primary peer. Therefore consider consistent here
		   as well. */
		drbd_info(peer_device, "Upgrading local disk to %s after unstable/weak (and no resync).\n",
			  drbd_disk_str(peer_disk_state));
		change_disk_state(peer_device->device, peer_disk_state, CS_VERBOSE, NULL);
		return;
	}

	rv = change_repl_state(peer_device, new_repl_state, CS_VERBOSE);
	if ((rv == SS_NOTHING_TO_DO || rv == SS_RESYNC_RUNNING) &&
	    (new_repl_state == L_WF_BITMAP_S || new_repl_state == L_WF_BITMAP_T)) {
		/* Those events might happen very quickly. In case we are still processing
		   the previous resync we need to re-enter that state. Schedule sending of
		   the bitmap here explicitly */
		peer_device->resync_again++;
		drbd_info(peer_device, "...postponing this until current resync finished\n");
	}
}

static void update_bitmap_slot_of_peer(struct drbd_peer_device *peer_device, int node_id, u64 bitmap_uuid)
{
	struct drbd_device *device = peer_device->device;

	if (peer_device->bitmap_uuids[node_id] && bitmap_uuid == 0) {
		/* If we learn from a neighbor that it no longer has a bitmap
		   against a third node, we need to deduce from that knowledge
		   that in the other direction the bitmap was cleared as well.
		 */
		struct drbd_peer_device *peer_device2;

		rcu_read_lock();
		peer_device2 = peer_device_by_node_id(peer_device->device, node_id);
		if (peer_device2) {
			int node_id2 = peer_device->connection->peer_node_id;
			peer_device2->bitmap_uuids[node_id2] = 0;
		}
		rcu_read_unlock();
	}

	if (node_id != device->resource->res_opts.node_id && bitmap_uuid != -1 && get_ldev(device)) {
		_drbd_uuid_push_history(device, bitmap_uuid);
		put_ldev(device);
	}
	peer_device->bitmap_uuids[node_id] = bitmap_uuid;
}

static int __receive_uuids(struct drbd_peer_device *peer_device, u64 node_mask)
{
	enum drbd_repl_state repl_state = peer_device->repl_state[NOW];
	struct drbd_device *device = peer_device->device;
	struct drbd_resource *resource = device->resource;
	int updated_uuids = 0, err = 0;
	bool bad_server;

	bad_server =
		repl_state < L_ESTABLISHED &&
		device->disk_state[NOW] < D_INCONSISTENT &&
		device->resource->role[NOW] == R_PRIMARY &&
		(device->exposed_data_uuid & ~UUID_PRIMARY) !=
		(peer_device->current_uuid & ~UUID_PRIMARY);

	if (peer_device->connection->agreed_pro_version < 110 && bad_server) {
		drbd_err(device, "Can only connect to data with current UUID=%016llX\n",
		    (unsigned long long)device->exposed_data_uuid);
		change_cstate(peer_device->connection, C_DISCONNECTING, CS_HARD);
		return -EIO;
	}

	if (get_ldev(device)) {
		int skip_initial_sync =
			repl_state == L_ESTABLISHED &&
			peer_device->connection->agreed_pro_version >= 90 &&
			drbd_current_uuid(device) == UUID_JUST_CREATED &&
			(peer_device->uuid_flags & UUID_FLAG_SKIP_INITIAL_SYNC);
		if (skip_initial_sync) {
			unsigned long irq_flags;

			drbd_info(device, "Accepted new current UUID, preparing to skip initial sync\n");
			drbd_bitmap_io(device, &drbd_bmio_clear_all_n_write,
					"clear_n_write from receive_uuids",
					BM_LOCK_SET | BM_LOCK_CLEAR | BM_LOCK_BULK, NULL);
			_drbd_uuid_set_current(device, peer_device->current_uuid);
			peer_device->comm_current_uuid = peer_device->current_uuid;
			peer_device->comm_uuid_flags = peer_device->uuid_flags;
			_drbd_uuid_set_bitmap(peer_device, 0);
			begin_state_change(device->resource, &irq_flags, CS_VERBOSE);
			/* FIXME: Note that req_lock was not taken here before! */
			__change_disk_state(device, D_UP_TO_DATE);
			__change_peer_disk_state(peer_device, D_UP_TO_DATE);
			end_state_change(device->resource, &irq_flags);
			updated_uuids = 1;
		}

		if (peer_device->uuid_flags & UUID_FLAG_NEW_DATAGEN) {
			drbd_warn(peer_device, "received new current UUID: %016llX "
				  "weak_nodes=%016llX\n", peer_device->current_uuid, node_mask);
			drbd_uuid_received_new_current(peer_device, peer_device->current_uuid, node_mask);
		}

		if (device->disk_state[NOW] > D_OUTDATED) {
			enum sync_strategy strategy;
			int unused_int;
			strategy = drbd_uuid_compare(peer_device, &unused_int, &unused_int);

			if (strategy == SYNC_TARGET_SET_BITMAP || strategy == SYNC_TARGET_USE_BITMAP) {
				struct drbd_resource *resource = device->resource;
				unsigned long irq_flags;

				begin_state_change(resource, &irq_flags, CS_VERBOSE);
				if (device->disk_state[NEW] > D_OUTDATED)
					__change_disk_state(device, D_OUTDATED);
				end_state_change(resource, &irq_flags);
			}
		}

		drbd_uuid_detect_finished_resyncs(peer_device);

		drbd_md_sync_if_dirty(device);
		put_ldev(device);
	} else if (device->disk_state[NOW] < D_INCONSISTENT &&
		   repl_state >= L_ESTABLISHED &&
		   peer_device->disk_state[NOW] == D_UP_TO_DATE &&
		   (peer_device->current_uuid & ~UUID_PRIMARY) !=
		   (device->exposed_data_uuid & ~UUID_PRIMARY) &&
		   (resource->role[NOW] == R_SECONDARY ||
		    test_and_clear_bit(NEW_CUR_UUID, &device->flags))) {

		spin_lock_irq(&resource->req_lock);
		if (resource->remote_state_change) {
			drbd_info(peer_device, "Delaying update of exposed data uuid\n");
			device->next_exposed_data_uuid = peer_device->current_uuid;
		} else
			updated_uuids = drbd_set_exposed_data_uuid(device, peer_device->current_uuid);
		spin_unlock_irq(&resource->req_lock);

	}

	if (updated_uuids)
		drbd_print_uuids(peer_device, "receiver updated UUIDs to");

	peer_device->uuid_node_mask = node_mask;

	if ((repl_state == L_SYNC_TARGET || repl_state == L_PAUSED_SYNC_T) &&
	    !(peer_device->uuid_flags & UUID_FLAG_STABLE) &&
	    !drbd_stable_sync_source_present(peer_device, NOW))
		set_bit(UNSTABLE_RESYNC, &peer_device->flags);

	/* send notification in case UUID flags have changed */
	drbd_broadcast_peer_device_state(peer_device);

	return err;
}

/* drbd 8.4 compat */
static int receive_uuids(struct drbd_connection *connection, struct packet_info *pi)
{
	const int node_id = connection->resource->res_opts.node_id;
	struct drbd_peer_device *peer_device;
	struct p_uuids *p = pi->data;
	int history_uuids, i;

	peer_device = conn_peer_device(connection, pi->vnr);
	if (!peer_device)
		return config_unknown_volume(connection, pi);

	history_uuids = min_t(int, HISTORY_UUIDS_V08,
			      ARRAY_SIZE(peer_device->history_uuids));

	peer_device->current_uuid = be64_to_cpu(p->current_uuid);
	peer_device->bitmap_uuids[node_id] = be64_to_cpu(p->bitmap_uuid);
	for (i = 0; i < history_uuids; i++)
		peer_device->history_uuids[i] = be64_to_cpu(p->history_uuids[i]);
	for (; i < ARRAY_SIZE(peer_device->history_uuids); i++)
		peer_device->history_uuids[i] = 0;
	peer_device->dirty_bits = be64_to_cpu(p->dirty_bits);
	peer_device->uuid_flags = be64_to_cpu(p->uuid_flags) | UUID_FLAG_STABLE;
	peer_device->uuids_received = true;

	return __receive_uuids(peer_device, 0);
}

static int receive_uuids110(struct drbd_connection *connection, struct packet_info *pi)
{
	struct drbd_peer_device *peer_device;
	struct p_uuids110 *p = pi->data;
	int bitmap_uuids, history_uuids, rest, i, pos, err;
	u64 bitmap_uuids_mask, node_mask;
	struct drbd_peer_md *peer_md = NULL;
	struct drbd_device *device;
	int not_allocated = -1;


	peer_device = conn_peer_device(connection, pi->vnr);
	if (!peer_device)
		return config_unknown_volume(connection, pi);

	device = peer_device->device;
	bitmap_uuids_mask = be64_to_cpu(p->bitmap_uuids_mask);
	if (bitmap_uuids_mask & ~(NODE_MASK(DRBD_PEERS_MAX) - 1))
		return -EIO;
	bitmap_uuids = hweight64(bitmap_uuids_mask);

	if (pi->size / sizeof(p->other_uuids[0]) < bitmap_uuids)
		return -EIO;
	history_uuids = pi->size / sizeof(p->other_uuids[0]) - bitmap_uuids;
	if (history_uuids > ARRAY_SIZE(peer_device->history_uuids))
		history_uuids = ARRAY_SIZE(peer_device->history_uuids);

	err = drbd_recv_into(connection, p->other_uuids,
			     (bitmap_uuids + history_uuids) *
			     sizeof(p->other_uuids[0]));
	if (err)
		return err;

	rest = pi->size - (bitmap_uuids + history_uuids) * sizeof(p->other_uuids[0]);
	if (rest) {
		err = ignore_remaining_packet(connection, rest);
		if (err)
			return err;
	}

	if (get_ldev(device)) {
		peer_md = device->ldev->md.peers;
		spin_lock_irq(&device->ldev->md.uuid_lock);
	}
	peer_device->current_uuid = be64_to_cpu(p->current_uuid);
	peer_device->dirty_bits = be64_to_cpu(p->dirty_bits);
	peer_device->uuid_flags = be64_to_cpu(p->uuid_flags);
	if (peer_device->uuid_flags & UUID_FLAG_HAS_UNALLOC) {
		not_allocated = peer_device->uuid_flags >> UUID_FLAG_UNALLOC_SHIFT;
		peer_device->uuid_flags &= ~UUID_FLAG_UNALLOC_MASK;
	}

	pos = 0;
	for (i = 0; i < ARRAY_SIZE(peer_device->bitmap_uuids); i++) {
		u64 bitmap_uuid;

		if (bitmap_uuids_mask & NODE_MASK(i)) {
			bitmap_uuid = be64_to_cpu(p->other_uuids[pos++]);

			if (peer_md && !(peer_md[i].flags & MDF_HAVE_BITMAP) &&
			    i != not_allocated)
				peer_md[i].flags |= MDF_NODE_EXISTS;
		} else {
			bitmap_uuid = -1;
		}

		update_bitmap_slot_of_peer(peer_device, i, bitmap_uuid);
	}

	for (i = 0; i < history_uuids; i++)
		peer_device->history_uuids[i] = be64_to_cpu(p->other_uuids[pos++]);
	while (i < ARRAY_SIZE(peer_device->history_uuids))
		peer_device->history_uuids[i++] = 0;
	peer_device->uuids_received = true;
	if (peer_md) {
		spin_unlock_irq(&device->ldev->md.uuid_lock);
		put_ldev(device);
	}

	node_mask = be64_to_cpu(p->node_mask);

	if (test_bit(INITIAL_STATE_PROCESSED, &peer_device->flags) &&
	    peer_device->connection->peer_role[NOW] == R_PRIMARY &&
	    peer_device->uuid_flags & UUID_FLAG_STABLE)
		check_resync_source(device, node_mask);

	err = __receive_uuids(peer_device, node_mask);

	if (!test_bit(RECONCILIATION_RESYNC, &peer_device->flags)) {
		if (peer_device->uuid_flags & UUID_FLAG_GOT_STABLE) {
			struct drbd_device *device = peer_device->device;

			if (peer_device->repl_state[NOW] == L_ESTABLISHED &&
			    drbd_device_stable(device, NULL) && get_ldev(device)) {
				drbd_send_uuids(peer_device, UUID_FLAG_RESYNC, 0);
				drbd_resync(peer_device, AFTER_UNSTABLE);
				put_ldev(device);
			}
		}

		if (peer_device->uuid_flags & UUID_FLAG_RESYNC) {
			if (get_ldev(device)) {
				bool dp = peer_device->uuid_flags & UUID_FLAG_DISKLESS_PRIMARY;
				drbd_resync(peer_device, dp ? DISKLESS_PRIMARY : AFTER_UNSTABLE);
				put_ldev(device);
			}
		}
	}

	return err;
}


/* If a primary looses connection to a SYNC_SOURCE node from us, then we
 * need to abort that resync. Why?
 *
 * When the primary sends a write we get that and write that as well. With
 * the peer_ack packet we will set that as out-of-sync towards the sync
 * source node.
 * When the resync process finds such bits we will request outdated
 * data from the sync source!
 *
 * -> better stop a resync from such a source.
 */
static void check_resync_source(struct drbd_device *device, u64 weak_nodes)
{
	struct drbd_peer_device *peer_device;

	rcu_read_lock();
	for_each_peer_device_rcu(peer_device, device) {
		enum drbd_repl_state repl_state = peer_device->repl_state[NOW];
		if ((repl_state == L_SYNC_TARGET || repl_state == L_PAUSED_SYNC_T) &&
		    NODE_MASK(peer_device->node_id) & weak_nodes) {
			rcu_read_unlock();
			goto abort;
		}
	}
	rcu_read_unlock();
	return;
abort:
	drbd_info(peer_device, "My sync source became a weak node, aborting resync!\n");
	change_repl_state(peer_device, L_ESTABLISHED, CS_VERBOSE);
	drbd_flush_workqueue(&device->resource->work);

	wait_event_interruptible(device->misc_wait,
				 peer_device->repl_state[NOW] <= L_ESTABLISHED  ||
				 atomic_read(&peer_device->rs_pending_cnt) == 0);

	drbd_rs_del_all(peer_device);
	peer_device->rs_total  = 0;
	peer_device->rs_failed = 0;
	peer_device->rs_paused = 0;
}

/**
 * convert_state() - Converts the peer's view of the cluster state to our point of view
 * @peer_state:	The state as seen by the peer.
 */
static union drbd_state convert_state(union drbd_state peer_state)
{
	union drbd_state state;

	static enum drbd_conn_state c_tab[] = {
		[L_OFF] = L_OFF,
		[L_ESTABLISHED] = L_ESTABLISHED,

		[L_STARTING_SYNC_S] = L_STARTING_SYNC_T,
		[L_STARTING_SYNC_T] = L_STARTING_SYNC_S,
		[C_DISCONNECTING] = C_TEAR_DOWN, /* C_NETWORK_FAILURE, */
		[C_CONNECTING] = C_CONNECTING,
		[L_VERIFY_S]       = L_VERIFY_T,
		[C_MASK]   = C_MASK,
	};

	state.i = peer_state.i;

	state.conn = c_tab[peer_state.conn];
	state.peer = peer_state.role;
	state.role = peer_state.peer;
	state.pdsk = peer_state.disk;
	state.disk = peer_state.pdsk;
	state.peer_isp = (peer_state.aftr_isp | peer_state.user_isp);

	return state;
}

static enum drbd_state_rv
__change_connection_state(struct drbd_connection *connection,
			  union drbd_state mask, union drbd_state val,
			  enum chg_state_flags flags)
{
	struct drbd_resource *resource = connection->resource;

	if (mask.role) {
		/* not allowed */
	}
	if (mask.susp) {
		mask.susp ^= -1;
		__change_io_susp_user(resource, val.susp);
	}
	if (mask.susp_nod) {
		mask.susp_nod ^= -1;
		__change_io_susp_no_data(resource, val.susp_nod);
	}
	if (mask.susp_fen) {
		mask.susp_fen ^= -1;
		__change_io_susp_fencing(connection, val.susp_fen);
	}
	if (mask.disk) {
		/* Handled in __change_peer_device_state(). */
		mask.disk ^= -1;
	}
	if (mask.conn) {
		mask.conn ^= -1;
		__change_cstate(connection,
				min_t(enum drbd_conn_state, val.conn, C_CONNECTED));
	}
	if (mask.pdsk) {
		/* Handled in __change_peer_device_state(). */
		mask.pdsk ^= -1;
	}
	if (mask.peer) {
		mask.peer ^= -1;
		__change_peer_role(connection, val.peer);
	}
	if (mask.i) {
		drbd_info(connection, "Remote state change: request %u/%u not "
		"understood\n", mask.i, val.i & mask.i);
		return SS_NOT_SUPPORTED;
	}
	return SS_SUCCESS;
}

static enum drbd_state_rv
__change_peer_device_state(struct drbd_peer_device *peer_device,
			   union drbd_state mask, union drbd_state val)
{
	struct drbd_device *device = peer_device->device;

	if (mask.peer) {
		/* Handled in __change_connection_state(). */
		mask.peer ^= -1;
	}
	if (mask.disk) {
		mask.disk ^= -1;
		__change_disk_state(device, val.disk);
	}

	if (mask.conn) {
		mask.conn ^= -1;
		__change_repl_state(peer_device,
				max_t(enum drbd_repl_state, val.conn, L_OFF));
	}
	if (mask.pdsk) {
		mask.pdsk ^= -1;
		__change_peer_disk_state(peer_device, val.pdsk);
	}
	if (mask.user_isp) {
		mask.user_isp ^= -1;
		__change_resync_susp_user(peer_device, val.user_isp);
	}
	if (mask.peer_isp) {
		mask.peer_isp ^= -1;
		__change_resync_susp_peer(peer_device, val.peer_isp);
	}
	if (mask.aftr_isp) {
		mask.aftr_isp ^= -1;
		__change_resync_susp_dependency(peer_device, val.aftr_isp);
	}
	if (mask.i) {
		drbd_info(peer_device, "Remote state change: request %u/%u not "
		"understood\n", mask.i, val.i & mask.i);
		return SS_NOT_SUPPORTED;
	}
	return SS_SUCCESS;
}

static union drbd_state
sanitize_outdate(struct drbd_peer_device *peer_device,
		 union drbd_state mask,
		 union drbd_state val)
{
	struct drbd_device *device = peer_device->device;
	union drbd_state result_mask = mask;

	if (val.pdsk == D_OUTDATED && peer_device->disk_state[NEW] < D_OUTDATED)
		result_mask.pdsk = 0;
	if (val.disk == D_OUTDATED && device->disk_state[NEW] < D_OUTDATED)
		result_mask.disk = 0;

	return result_mask;
}

static void log_openers(struct drbd_resource *resource)
{
	struct drbd_device *device;
	int vnr;

	mutex_lock(&resource->open_release);
	rcu_read_lock();
	idr_for_each_entry(&resource->devices, device, vnr) {
		struct opener *opener;

		opener = list_first_entry_or_null(&device->openers.list, struct opener, list);
		if (opener)
			drbd_warn(device, "Held open by %s(%d)\n", opener->comm, opener->pid);
	}
	rcu_read_unlock();
	mutex_unlock(&resource->open_release);
}

/**
 * change_connection_state()  -  change state of a connection and all its peer devices
 *
 * Also changes the state of the peer devices' devices and of the resource.
 * Cluster-wide state changes are not supported.
 */
static enum drbd_state_rv
change_connection_state(struct drbd_connection *connection,
			union drbd_state mask,
			union drbd_state val,
			struct twopc_reply *reply,
			enum chg_state_flags flags)
{
	struct drbd_resource *resource = connection->resource;
	long t = resource->res_opts.auto_promote_timeout * HZ / 10;
	bool is_disconnect = reply->is_disconnect;
	bool is_connect = reply->is_connect;
	struct drbd_peer_device *peer_device;
	unsigned long irq_flags;
	enum drbd_state_rv rv;
	int vnr;

	mask = convert_state(mask);
	val = convert_state(val);

	if (is_connect && connection->agreed_pro_version >= 118) {
		if (flags & CS_PREPARE)
			conn_connect2(connection);
		if (flags & CS_ABORT)
			abort_connect(connection);
	}
retry:
	begin_state_change(resource, &irq_flags, flags & ~CS_VERBOSE);
	idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
		union drbd_state l_mask;
		l_mask = is_disconnect ? sanitize_outdate(peer_device, mask, val) : mask;
		rv = __change_peer_device_state(peer_device, l_mask, val);
		if (rv < SS_SUCCESS)
			goto fail;
	}
	rv = __change_connection_state(connection, mask, val, flags);
	if (rv < SS_SUCCESS)
		goto fail;

	if (reply) {
		u64 directly_reachable = directly_connected_nodes(resource, NEW) |
			NODE_MASK(resource->res_opts.node_id);

		if (reply->primary_nodes & ~directly_reachable)
			__outdate_myself(resource);
	}

	if (is_connect && connection->agreed_pro_version >= 117)
		apply_connect(connection, flags & CS_PREPARED);
	rv = end_state_change(resource, &irq_flags);
out:

	if ((rv == SS_NO_UP_TO_DATE_DISK && resource->role[NOW] != R_PRIMARY) ||
	    rv == SS_PRIMARY_READER) {
		/* Most probably udev opened it read-only. That might happen
		   if it was demoted very recently. Wait up to one second. */
		t = wait_event_interruptible_timeout(resource->state_wait,
						     drbd_open_ro_count(resource) == 0,
						     t);
		if (t > 0)
			goto retry;
	}

	if (rv < SS_SUCCESS) {
		drbd_err(resource, "State change failed: %s\n", drbd_set_st_err_str(rv));
		if (rv == SS_PRIMARY_READER)
			log_openers(resource);
	}

	return rv;
fail:
	abort_state_change(resource, &irq_flags);
	goto out;
}

/**
 * change_peer_device_state()  -  change state of a peer and its connection
 *
 * Also changes the state of the peer device's device and of the resource.
 * Cluster-wide state changes are not supported.
 */
static enum drbd_state_rv
change_peer_device_state(struct drbd_peer_device *peer_device,
			 union drbd_state mask,
			 union drbd_state val,
			 enum chg_state_flags flags)
{
	struct drbd_connection *connection = peer_device->connection;
	unsigned long irq_flags;
	enum drbd_state_rv rv;

	mask = convert_state(mask);
	val = convert_state(val);

	begin_state_change(connection->resource, &irq_flags, flags);
	rv = __change_peer_device_state(peer_device, mask, val);
	if (rv < SS_SUCCESS)
		goto fail;
	rv = __change_connection_state(connection, mask, val, flags);
	if (rv < SS_SUCCESS)
		goto fail;
	rv = end_state_change(connection->resource, &irq_flags);
out:
	return rv;
fail:
	abort_state_change(connection->resource, &irq_flags);
	goto out;
}

static int receive_req_state(struct drbd_connection *connection, struct packet_info *pi)
{
	struct drbd_resource *resource = connection->resource;
	struct drbd_peer_device *peer_device = NULL;
	struct p_req_state *p = pi->data;
	union drbd_state mask, val;
	enum chg_state_flags flags = CS_VERBOSE | CS_LOCAL_ONLY | CS_TWOPC;
	enum drbd_state_rv rv;
	int vnr = -1;

	if (!expect(connection, connection->agreed_pro_version < 110)) {
		drbd_err(connection, "Packet %s not allowed in protocol version %d\n",
			 drbd_packet_name(pi->cmd),
			 connection->agreed_pro_version);
		return -EIO;
	}

	mask.i = be32_to_cpu(p->mask);
	val.i = be32_to_cpu(p->val);

	/* P_STATE_CHG_REQ packets must have a valid vnr.  P_CONN_ST_CHG_REQ
	 * packets have an undefined vnr. */
	if (pi->cmd == P_STATE_CHG_REQ) {
		peer_device = conn_peer_device(connection, pi->vnr);
		if (!peer_device) {
			if (mask.i == ((union drbd_state){{.conn = conn_MASK}}).i &&
			    val.i == ((union drbd_state){{.conn = L_OFF}}).i) {
				/* The peer removed this volume, we do not have it... */
				drbd_send_sr_reply(connection, vnr, SS_NOTHING_TO_DO);
				return 0;
			}

			return -EIO;
		}
		vnr = peer_device->device->vnr;
	}

	rv = SS_SUCCESS;
	spin_lock_irq(&resource->req_lock);
	if (resource->remote_state_change)
		rv = SS_CONCURRENT_ST_CHG;
	else
		resource->remote_state_change = true;
	spin_unlock_irq(&resource->req_lock);

	if (rv != SS_SUCCESS) {
		drbd_info(connection, "Rejecting concurrent remote state change\n");
		drbd_send_sr_reply(connection, vnr, rv);
		return 0;
	}

	/* Send the reply before carrying out the state change: this is needed
	 * for connection state changes which close the network connection.  */
	if (peer_device) {
		rv = change_peer_device_state(peer_device, mask, val, flags | CS_PREPARE);
		drbd_send_sr_reply(connection, vnr, rv);
		rv = change_peer_device_state(peer_device, mask, val, flags | CS_PREPARED);
		if (rv >= SS_SUCCESS)
			drbd_md_sync_if_dirty(peer_device->device);
	} else {
		flags |= CS_IGN_OUTD_FAIL;
		rv = change_connection_state(connection, mask, val, NULL, flags | CS_PREPARE);
		drbd_send_sr_reply(connection, vnr, rv);
		change_connection_state(connection, mask, val, NULL, flags | CS_PREPARED);
	}

	spin_lock_irq(&resource->req_lock);
	resource->remote_state_change = false;
	spin_unlock_irq(&resource->req_lock);
	wake_up(&resource->twopc_wait);
	queue_queued_twopc(resource);

	return 0;
}

int abort_nested_twopc_work(struct drbd_work *work, int cancel)
{
	struct drbd_resource *resource =
		container_of(work, struct drbd_resource, twopc_work);
	bool prepared = false;

	spin_lock_irq(&resource->req_lock);
	if (resource->twopc_reply.initiator_node_id != -1) {
		struct drbd_connection *connection, *tmp;
		resource->remote_state_change = false;
		resource->twopc_reply.initiator_node_id = -1;
		list_for_each_entry_safe(connection, tmp, &resource->twopc_parents, twopc_parent_list) {
			kref_debug_put(&connection->kref_debug, 9);
			kref_put(&connection->kref, drbd_destroy_connection);
		}
		INIT_LIST_HEAD(&resource->twopc_parents);

		prepared = true;
	}
	resource->twopc_work.cb = NULL;
	spin_unlock_irq(&resource->req_lock);
	wake_up(&resource->twopc_wait);
	queue_queued_twopc(resource);

	if (prepared)
		abort_prepared_state_change(resource);
	return 0;
}

void twopc_timer_fn(struct timer_list *t)
{
	struct drbd_resource *resource = from_timer(resource, t, twopc_timer);
	unsigned long irq_flags;

	spin_lock_irqsave(&resource->req_lock, irq_flags);
	if (resource->twopc_work.cb == NULL) {
		drbd_err(resource, "Two-phase commit %u timeout\n",
			   resource->twopc_reply.tid);
		resource->twopc_work.cb = abort_nested_twopc_work;
		drbd_queue_work(&resource->work, &resource->twopc_work);
	} else {
		mod_timer(&resource->twopc_timer, jiffies + HZ/10);
	}
	spin_unlock_irqrestore(&resource->req_lock, irq_flags);
}

static enum drbd_state_rv outdate_if_weak(struct drbd_resource *resource,
					  struct twopc_reply *reply,
					  enum chg_state_flags flags)
{
	u64 directly_reachable = directly_connected_nodes(resource, NOW) |
		NODE_MASK(resource->res_opts.node_id);

	if (reply->primary_nodes & ~directly_reachable) {
		unsigned long irq_flags;

		begin_state_change(resource, &irq_flags, flags);
		__outdate_myself(resource);
		return end_state_change(resource, &irq_flags);
	}

	return SS_NOTHING_TO_DO;
}

bool drbd_have_local_disk(struct drbd_resource *resource)
{
	struct drbd_device *device;
	int vnr;

	rcu_read_lock();
	idr_for_each_entry(&resource->devices, device, vnr) {
		if (device->disk_state[NOW] > D_DISKLESS) {
			rcu_read_unlock();
			return true;
		}
	}
	rcu_read_unlock();
	return false;
}

static enum drbd_state_rv
far_away_change(struct drbd_connection *connection, union drbd_state mask,
		union drbd_state val, struct twopc_reply *reply,
		enum chg_state_flags flags)
{
	struct drbd_resource *resource = connection->resource;
	int vnr = resource->twopc_reply.vnr;

	if (mask.i == 0 && val.i == 0 &&
	    resource->role[NOW] == R_PRIMARY && vnr == -1) {
		/* A node far away test if there are primaries. I am the guy he
		   is concerned about... He learned about me in the CS_PREPARE phase.
		   Since he is committing it I know that he is outdated now... */
		struct drbd_connection *affected_connection;
		int initiator_node_id = resource->twopc_reply.initiator_node_id;

		affected_connection = drbd_get_connection_by_node_id(resource, initiator_node_id);
		if (affected_connection) {
			unsigned long irq_flags;
			enum drbd_state_rv rv;

			begin_state_change(resource, &irq_flags, flags);
			__downgrade_peer_disk_states(affected_connection, D_OUTDATED);
			rv = end_state_change(resource, &irq_flags);
			kref_put(&affected_connection->kref, drbd_destroy_connection);
			return rv;
		}
	}
	if (flags & CS_PREPARE && mask.role == role_MASK && val.role == R_PRIMARY &&
	    resource->role[NOW] == R_PRIMARY) {
		struct net_conf *nc;
		bool two_primaries_allowed = false;

		rcu_read_lock();
		nc = rcu_dereference(connection->transport.net_conf);
		if (nc)
			two_primaries_allowed = nc->two_primaries;
		rcu_read_unlock();
		if (!two_primaries_allowed)
			return SS_TWO_PRIMARIES;

		/* A node further away wants to become primary. In case I am
		   primary allow it only when I am diskless. See
		   also check_primaries_distances() in drbd_state.c */
		if (drbd_have_local_disk(resource))
			return SS_WEAKLY_CONNECTED;
	}
	return outdate_if_weak(resource, reply, flags);
}

enum csc_rv {
	CSC_CLEAR,
	CSC_REJECT,
	CSC_ABORT_LOCAL,
	CSC_QUEUE,
	CSC_TID_MISS,
	CSC_MATCH,
};

static enum csc_rv
check_concurrent_transactions(struct drbd_resource *resource, struct twopc_reply *new_r)
{
	struct twopc_reply *ongoing = &resource->twopc_reply;

	if (!resource->remote_state_change)
		return CSC_CLEAR;

	if (new_r->initiator_node_id < ongoing->initiator_node_id) {
		if (ongoing->initiator_node_id == resource->res_opts.node_id)
			return CSC_ABORT_LOCAL;
		else
			return CSC_QUEUE;
	} else if (new_r->initiator_node_id > ongoing->initiator_node_id) {
		return CSC_REJECT;
	}
	if (new_r->tid != ongoing->tid)
		return CSC_TID_MISS;

	return CSC_MATCH;
}


enum alt_rv {
	ALT_LOCKED,
	ALT_MATCH,
	ALT_TIMEOUT,
};

static enum alt_rv when_done_lock(struct drbd_resource *resource, unsigned int for_tid)
{
	spin_lock_irq(&resource->req_lock);
	if (!resource->remote_state_change)
		return ALT_LOCKED;
	spin_unlock_irq(&resource->req_lock);
	if (resource->twopc_reply.tid == for_tid)
		return ALT_MATCH;

	return ALT_TIMEOUT;
}
static enum alt_rv abort_local_transaction(struct drbd_resource *resource, unsigned int for_tid)
{
	long t = twopc_timeout(resource) / 8;
	enum alt_rv rv;

	set_bit(TWOPC_ABORT_LOCAL, &resource->flags);
	spin_unlock_irq(&resource->req_lock);
	wake_up(&resource->state_wait);
	wait_event_timeout(resource->twopc_wait,
			   (rv = when_done_lock(resource, for_tid)) != ALT_TIMEOUT, t);
	clear_bit(TWOPC_ABORT_LOCAL, &resource->flags);
	return rv;
}

static void arm_queue_twopc_timer(struct drbd_resource *resource)
{
	struct queued_twopc *q;
	q = list_first_entry_or_null(&resource->queued_twopc, struct queued_twopc, w.list);

	if (q) {
		unsigned long t = twopc_timeout(resource) / 4;
		mod_timer(&resource->queued_twopc_timer, q->start_jif + t);
	} else {
		del_timer(&resource->queued_twopc_timer);
	}
}

static int queue_twopc(struct drbd_connection *connection, struct twopc_reply *twopc, struct packet_info *pi)
{
	struct drbd_resource *resource = connection->resource;
	struct queued_twopc *q;
	bool was_empty, already_queued = false;

	spin_lock_irq(&resource->queued_twopc_lock);
	list_for_each_entry(q, &resource->queued_twopc, w.list) {
		if (q->reply.tid == twopc->tid &&
		    q->reply.initiator_node_id == twopc->initiator_node_id &&
		    q->connection == connection)
			already_queued = true;
	}
	spin_unlock_irq(&resource->queued_twopc_lock);

	if (already_queued)
		return 0;

	q = kmalloc(sizeof(*q), GFP_NOIO);
	if (!q)
		return -ENOMEM;

	q->reply = *twopc;
	q->packet_data = *(struct p_twopc_request *)pi->data;
	q->packet_info = *pi;
	q->packet_info.data = &q->packet_data;
	kref_get(&connection->kref);
	kref_debug_get(&connection->kref_debug, 16);
	q->connection = connection;
	q->start_jif = jiffies;

	spin_lock_irq(&resource->queued_twopc_lock);
	was_empty = list_empty(&resource->queued_twopc);
	list_add_tail(&q->w.list, &resource->queued_twopc);
	if (was_empty)
		arm_queue_twopc_timer(resource);
	spin_unlock_irq(&resource->queued_twopc_lock);

	return 0;
}

static int queued_twopc_work(struct drbd_work *w, int cancel)
{
	struct queued_twopc *q = container_of(w, struct queued_twopc, w), *q2, *tmp;
	struct drbd_connection *connection = q->connection;
	struct drbd_resource *resource = connection->resource;
	unsigned long t = twopc_timeout(resource) / 4;
	LIST_HEAD(work_list);

	/* Look for more for the same TID... */
	spin_lock_irq(&resource->queued_twopc_lock);
	list_for_each_entry_safe(q2, tmp, &resource->queued_twopc, w.list) {
		if (q2->reply.tid == q->reply.tid &&
		    q2->reply.initiator_node_id == q->reply.initiator_node_id)
			list_move_tail(&q2->w.list, &work_list);
	}
	spin_unlock_irq(&resource->queued_twopc_lock);

	while (true) {
		if (jiffies - q->start_jif >= t || cancel) {
			if (!cancel)
				drbd_info(connection, "Rejecting concurrent "
					  "remote state change %u because of "
					  "state change %u takes too long\n",
					  q->reply.tid,
					  resource->twopc_reply.tid);
			drbd_send_twopc_reply(connection, P_TWOPC_RETRY, &q->reply);
		} else {
			process_twopc(connection, &q->reply, &q->packet_info, q->start_jif);
		}

		kref_debug_put(&connection->kref_debug, 16);
		kref_put(&connection->kref, drbd_destroy_connection);
		kfree(q);

		q = list_first_entry_or_null(&work_list, struct queued_twopc, w.list);
		if (q) {
			list_del(&q->w.list);
			connection = q->connection;
		} else
			break;
	}

	return 0;
}

void queued_twopc_timer_fn(struct timer_list *t)
{
	struct drbd_resource *resource = from_timer(resource, t, queued_twopc_timer);
	struct queued_twopc *q;
	unsigned long irq_flags;
	unsigned long time = twopc_timeout(resource) / 4;

	spin_lock_irqsave(&resource->queued_twopc_lock, irq_flags);
	q = list_first_entry_or_null(&resource->queued_twopc, struct queued_twopc, w.list);
	if (q) {
		if (jiffies - q->start_jif >= time) {
			resource->starting_queued_twopc = q;
			list_del(&q->w.list);
		}
	}
	spin_unlock_irqrestore(&resource->queued_twopc_lock, irq_flags);

	if (q) {
		q->w.cb = &queued_twopc_work;
		drbd_queue_work(&resource->work , &q->w);
	}
}

void queue_queued_twopc(struct drbd_resource *resource)
{
	struct queued_twopc *q;
	unsigned long irq_flags;

	spin_lock_irqsave(&resource->queued_twopc_lock, irq_flags);
	q = list_first_entry_or_null(&resource->queued_twopc, struct queued_twopc, w.list);
	if (q) {
		resource->starting_queued_twopc = q;
		list_del(&q->w.list);
		arm_queue_twopc_timer(resource);
	}
	spin_unlock_irqrestore(&resource->queued_twopc_lock, irq_flags);

	if (!q)
		return;

	q->w.cb = &queued_twopc_work;
	drbd_queue_work(&resource->work , &q->w);
}

static int abort_starting_twopc(struct drbd_resource *resource, struct twopc_reply *twopc)
{
	struct queued_twopc *q = resource->starting_queued_twopc;

	if (q && q->reply.tid == twopc->tid) {
		q->reply.is_aborted = 1;
		return 0;
	}

	return -ENOENT;
}

static int abort_queued_twopc(struct drbd_resource *resource, struct twopc_reply *twopc)
{
	struct queued_twopc *q;
	unsigned long irq_flags;

	spin_lock_irqsave(&resource->queued_twopc_lock, irq_flags);
	list_for_each_entry(q, &resource->queued_twopc, w.list) {
		if (q->reply.tid == twopc->tid) {
			list_del(&q->w.list);
			goto found;
		}
	}
	q = NULL;
found:
	spin_unlock_irqrestore(&resource->queued_twopc_lock, irq_flags);

	if (q) {
		kref_put(&q->connection->kref, drbd_destroy_connection);
		kfree(q);
		return 0;
	}

	return -ENOENT;
}

static int receive_twopc(struct drbd_connection *connection, struct packet_info *pi)
{
	struct drbd_resource *resource = connection->resource;
	struct p_twopc_request *p = pi->data;
	struct twopc_reply reply = {0};
	int rv;

	reply.vnr = pi->vnr;
	reply.tid = be32_to_cpu(p->tid);
	reply.initiator_node_id = be32_to_cpu(p->initiator_node_id);
	reply.target_node_id = be32_to_cpu(p->target_node_id);
	reply.reachable_nodes = directly_connected_nodes(resource, NOW) |
				NODE_MASK(resource->res_opts.node_id);

	if (pi->cmd == P_TWOPC_PREPARE &&
			reply.initiator_node_id == connection->peer_node_id &&
			reply.target_node_id == resource->res_opts.node_id) {
		/* Clear the relevant flags at the start of a connection
		 * attempt from this peer. They must be cleared before we
		 * receive any more packets, because the state packets follow
		 * after this one even when this two-phase commit is queued. If
		 * the two-phase commit is not a connection attempt, clearing
		 * the flags is harmless. The peer will never initiate a
		 * concurrent two-phase commit while a connection attempt is
		 * ongoing. */
		clear_bit(CONN_HANDSHAKE_DISCONNECT, &connection->flags);
		clear_bit(CONN_HANDSHAKE_RETRY, &connection->flags);
		clear_bit(CONN_HANDSHAKE_READY, &connection->flags);
	}

	rv = process_twopc(connection, &reply, pi, jiffies);

	return rv;
}

static void nested_twopc_abort(struct drbd_resource *resource, int vnr, enum drbd_packet cmd,
			       struct p_twopc_request *request)
{
	struct drbd_connection *connection;
	u64 nodes_to_reach, reach_immediately, im;

	spin_lock_irq(&resource->req_lock);
	nodes_to_reach = be64_to_cpu(request->nodes_to_reach);
	reach_immediately = directly_connected_nodes(resource, NOW) & nodes_to_reach;
	nodes_to_reach &= ~(reach_immediately | NODE_MASK(resource->res_opts.node_id));
	request->nodes_to_reach = cpu_to_be64(nodes_to_reach);
	spin_unlock_irq(&resource->req_lock);

	for_each_connection_ref(connection, im, resource) {
		u64 mask = NODE_MASK(connection->peer_node_id);
		if (reach_immediately & mask)
			conn_send_twopc_request(connection, vnr, cmd, request);
	}
}

static bool is_prepare(enum drbd_packet cmd)
{
	return cmd == P_TWOPC_PREP_RSZ || cmd == P_TWOPC_PREPARE;
}


enum determine_dev_size
drbd_commit_size_change(struct drbd_device *device, struct resize_parms *rs, u64 nodes_to_reach)
{
	struct twopc_resize *tr = &device->resource->twopc_resize;
	enum determine_dev_size dd;
	uint64_t my_usize;

	if (!get_ldev(device)) {
		drbd_set_my_capacity(device, tr->new_size);
		return DS_UNCHANGED; /* Not entirely true, but we are diskless... */
	}

	rcu_read_lock();
	my_usize = rcu_dereference(device->ldev->disk_conf)->disk_size;
	rcu_read_unlock();

	if (my_usize != tr->user_size) {
		struct disk_conf *old_disk_conf, *new_disk_conf;

		new_disk_conf = kzalloc(sizeof(struct disk_conf), GFP_KERNEL);
		if (!new_disk_conf) {
			drbd_err(device, "Allocation of new disk_conf failed\n");
			device->ldev->disk_conf->disk_size = tr->user_size;
			goto cont;
		}

		old_disk_conf = device->ldev->disk_conf;
		*new_disk_conf = *old_disk_conf;
		new_disk_conf->disk_size = tr->user_size;

		rcu_assign_pointer(device->ldev->disk_conf, new_disk_conf);
		synchronize_rcu();
		kfree(old_disk_conf);

		drbd_info(device, "New u_size %llu sectors\n",
			  (unsigned long long)tr->user_size);
	}
cont:
	dd = drbd_determine_dev_size(device, tr->new_size, tr->dds_flags | DDSF_2PC, rs);

	if (dd > DS_UNCHANGED) { /* DS_SHRUNK, DS_GREW, DS_GREW_FROM_ZERO */
		struct drbd_peer_device *peer_device;
		u64 im;

		for_each_peer_device_ref(peer_device, im, device) {
			if (peer_device->repl_state[NOW] != L_ESTABLISHED ||
			    peer_device->disk_state[NOW] < D_INCONSISTENT)
				continue;

			/* update cached sizes, relevant for the next handshake
			 * of a currently unconnected peer. */
			peer_device->c_size = tr->new_size;
			peer_device->u_size = tr->user_size;
			if (dd >= DS_GREW) {
				if (tr->new_size > peer_device->d_size)
					peer_device->d_size = tr->new_size;

				if (tr->new_size > peer_device->max_size)
					peer_device->max_size = tr->new_size;
			} else if (dd == DS_SHRUNK) {
				if (tr->new_size < peer_device->d_size)
					peer_device->d_size = tr->new_size;

				if (tr->new_size < peer_device->max_size)
					peer_device->max_size = tr->new_size;
			}
		}
	}

	if (dd == DS_GREW && !(tr->dds_flags & DDSF_NO_RESYNC)) {
		struct drbd_resource *resource = device->resource;
		const int my_node_id = resource->res_opts.node_id;
		struct drbd_peer_device *peer_device;
		u64 im;

		for_each_peer_device_ref(peer_device, im, device) {
			if (peer_device->repl_state[NOW] != L_ESTABLISHED ||
			    peer_device->disk_state[NOW] < D_INCONSISTENT)
				continue;

			if (tr->diskful_primary_nodes) {
				if (tr->diskful_primary_nodes & NODE_MASK(my_node_id)) {
					enum drbd_repl_state resync;
					if (peer_device->connection->peer_role[NOW] == R_SECONDARY) {
						resync = L_SYNC_SOURCE;
					} else /* peer == R_PRIMARY */ {
						resync = peer_device->node_id < my_node_id ?
							L_SYNC_TARGET : L_SYNC_SOURCE;
					}
					drbd_start_resync(peer_device, resync);
				} else {
					if (peer_device->connection->peer_role[NOW] == R_PRIMARY)
						drbd_start_resync(peer_device, L_SYNC_TARGET);
					/* else  no resync */
				}
			} else {
				if (resource->twopc_parent_nodes & NODE_MASK(peer_device->node_id))
					drbd_start_resync(peer_device, L_SYNC_TARGET);
				else if (nodes_to_reach & NODE_MASK(peer_device->node_id))
					drbd_start_resync(peer_device, L_SYNC_SOURCE);
				/* else  no resync */
			}
		}
	}

	put_ldev(device);
	return dd;
}

enum drbd_state_rv drbd_support_2pc_resize(struct drbd_resource *resource)
{
	struct drbd_connection *connection;
	enum drbd_state_rv rv = SS_SUCCESS;

	rcu_read_lock();
	for_each_connection_rcu(connection, resource) {
		if (connection->cstate[NOW] == C_CONNECTED &&
		    connection->agreed_pro_version < 112) {
			rv = SS_NOT_SUPPORTED;
			break;
		}
	}
	rcu_read_unlock();

	return rv;
}

static int process_twopc(struct drbd_connection *connection,
			 struct twopc_reply *reply,
			 struct packet_info *pi,
			 unsigned long receive_jif)
{
	struct drbd_connection *affected_connection = connection;
	struct drbd_resource *resource = connection->resource;
	struct drbd_peer_device *peer_device = NULL;
	struct p_twopc_request *p = pi->data;
	union drbd_state mask = {}, val = {};
	enum chg_state_flags flags = CS_VERBOSE | CS_LOCAL_ONLY;
	enum drbd_state_rv rv = SS_SUCCESS;
	enum csc_rv csc_rv;

	/* Check for concurrent transactions and duplicate packets. */
	spin_lock_irq(&resource->req_lock);

	csc_rv = check_concurrent_transactions(resource, reply);

	if (csc_rv == CSC_CLEAR && pi->cmd != P_TWOPC_ABORT) {
		if (!is_prepare(pi->cmd)) {
			/* We have committed or aborted this transaction already. */
			spin_unlock_irq(&resource->req_lock);
			drbd_debug(connection, "Ignoring %s packet %u\n",
				   drbd_packet_name(pi->cmd),
				   reply->tid);
			return 0;
		}
		if (reply->is_aborted) {
			spin_unlock_irq(&resource->req_lock);
			return 0;
		}
		resource->starting_queued_twopc = NULL;
		resource->remote_state_change = true;
		resource->twopc_type = pi->cmd == P_TWOPC_PREPARE ? TWOPC_STATE_CHANGE : TWOPC_RESIZE;
		resource->twopc_prepare_reply_cmd = 0;
		resource->twopc_parent_nodes = NODE_MASK(connection->peer_node_id);
		clear_bit(TWOPC_EXECUTED, &resource->flags);
	} else if (csc_rv == CSC_MATCH && !is_prepare(pi->cmd)) {
		flags |= CS_PREPARED;

		if (test_and_set_bit(TWOPC_EXECUTED, &resource->flags)) {
			spin_unlock_irq(&resource->req_lock);
			drbd_info(connection, "Ignoring redundant %s packet %u.\n",
				  drbd_packet_name(pi->cmd),
				  reply->tid);
			return 0;
		}
	} else if (csc_rv == CSC_ABORT_LOCAL && is_prepare(pi->cmd)) {
		enum alt_rv alt_rv;

		drbd_info(connection, "Aborting local state change %u to yield to remote "
			  "state change %u.\n",
			  resource->twopc_reply.tid,
			  reply->tid);
		alt_rv = abort_local_transaction(resource, reply->tid);
		if (alt_rv == ALT_MATCH) {
			/* abort_local_transaction() comes back unlocked in this case... */
			goto match;
		} else if (alt_rv == ALT_TIMEOUT) {
			/* abort_local_transaction() comes back unlocked in this case... */
			drbd_info(connection, "Aborting local state change %u "
				  "failed. Rejecting remote state change %u.\n",
				  resource->twopc_reply.tid,
				  reply->tid);
			drbd_send_twopc_reply(connection, P_TWOPC_RETRY, reply);
			return 0;
		}
		/* abort_local_transaction() returned with the req_lock */
		if (reply->is_aborted) {
			spin_unlock_irq(&resource->req_lock);
			return 0;
		}
		resource->starting_queued_twopc = NULL;
		resource->remote_state_change = true;
		resource->twopc_type = pi->cmd == P_TWOPC_PREPARE ? TWOPC_STATE_CHANGE : TWOPC_RESIZE;
		resource->twopc_parent_nodes = NODE_MASK(connection->peer_node_id);
		resource->twopc_prepare_reply_cmd = 0;
		clear_bit(TWOPC_EXECUTED, &resource->flags);
	} else if (pi->cmd == P_TWOPC_ABORT) {
		/* crc_rc != CRC_MATCH */
		int err;

		err = abort_starting_twopc(resource, reply);
		spin_unlock_irq(&resource->req_lock);
		if (err) {
			err = abort_queued_twopc(resource, reply);
			if (err)
				drbd_info(connection, "Ignoring %s packet %u.\n",
					  drbd_packet_name(pi->cmd),
					  reply->tid);
		}

		nested_twopc_abort(resource, pi->vnr, pi->cmd, p);
		return 0;
	} else {
		spin_unlock_irq(&resource->req_lock);

		if (csc_rv == CSC_REJECT) {
		reject:
			drbd_info(connection, "Rejecting concurrent "
				  "remote state change %u because of "
				  "state change %u\n",
				  reply->tid,
				  resource->twopc_reply.tid);
			drbd_send_twopc_reply(connection, P_TWOPC_RETRY, reply);
			return 0;
		}

		if (is_prepare(pi->cmd)) {
			if (csc_rv == CSC_QUEUE) {
				int err = queue_twopc(connection, reply, pi);
				if (err)
					goto reject;
			} else if (csc_rv == CSC_TID_MISS) {
				goto reject;
			} else if (csc_rv == CSC_MATCH) {
				/* We have prepared this transaction already. */
				enum drbd_packet reply_cmd;

			match:
				spin_lock_irq(&resource->req_lock);
				resource->twopc_parent_nodes |= NODE_MASK(connection->peer_node_id);
				reply_cmd = resource->twopc_prepare_reply_cmd;
				if (!reply_cmd) {
					kref_get(&connection->kref);
					kref_debug_get(&connection->kref_debug, 9);
					list_add(&connection->twopc_parent_list,
						 &resource->twopc_parents);
				}
				spin_unlock_irq(&resource->req_lock);

				if (reply_cmd) {
					drbd_send_twopc_reply(connection, reply_cmd,
							      &resource->twopc_reply);
				} else {
					/* if a node sends us a prepare, that means he has
					   prepared this himsilf successfully. */
					set_bit(TWOPC_YES, &connection->flags);

					if (cluster_wide_reply_ready(resource)) {
						if (resource->twopc_work.cb == NULL) {
							resource->twopc_work.cb = nested_twopc_work;
							drbd_queue_work(&resource->work, &resource->twopc_work);
						}
					}
				}
			}
		} else {
			drbd_info(connection, "Ignoring %s packet %u "
				  "current processing state change %u\n",
				  drbd_packet_name(pi->cmd),
				  reply->tid,
				  resource->twopc_reply.tid);
		}
		return 0;
	}

	if (reply->initiator_node_id != connection->peer_node_id) {
		/*
		 * This is an indirect request.  Unless we are directly
		 * connected to the initiator as well as indirectly, we don't
		 * have connection or peer device objects for this peer.
		 */
		affected_connection = drbd_connection_by_node_id(resource, reply->initiator_node_id);
	}

	if (reply->target_node_id != -1 &&
	    reply->target_node_id != resource->res_opts.node_id) {
		affected_connection = NULL;
	}

	if (resource->twopc_type == TWOPC_STATE_CHANGE) {
		mask.i = be32_to_cpu(p->mask);
		val.i = be32_to_cpu(p->val);
	}

	if (affected_connection && affected_connection->cstate[NOW] < C_CONNECTED &&
	    mask.conn == 0)
		affected_connection = NULL;

	if (pi->vnr != -1 && affected_connection) {
		peer_device = conn_peer_device(affected_connection, pi->vnr);
		/* If we do not know the peer_device, then we are fine with
		   whatever is going on in the cluster. E.g. detach and del-minor
		   one each node, one after the other */

		affected_connection = NULL; /* It is intended for a peer_device! */
	}

	if (mask.conn == conn_MASK) {
		u64 m = NODE_MASK(reply->initiator_node_id);

		if (val.conn == C_CONNECTED) {
			reply->reachable_nodes |= m;
			if (affected_connection)
				reply->is_connect = 1;
		}
		if (val.conn == C_DISCONNECTING) {
			reply->reachable_nodes &= ~m;
			reply->is_disconnect = 1;
		}
	}

	if (pi->cmd == P_TWOPC_PREPARE) {
		reply->primary_nodes = be64_to_cpu(p->primary_nodes);
		if (resource->role[NOW] == R_PRIMARY) {
			reply->primary_nodes |= NODE_MASK(resource->res_opts.node_id);
			reply->weak_nodes = ~reply->reachable_nodes;
		}
	}
	if (pi->cmd == P_TWOPC_PREP_RSZ) {
		struct drbd_device *device;

		device = (peer_device ?: conn_peer_device(connection, pi->vnr))->device;
		if (get_ldev(device)) {
			if (resource->role[NOW] == R_PRIMARY)
				reply->diskful_primary_nodes = NODE_MASK(resource->res_opts.node_id);
			reply->max_possible_size = drbd_local_max_size(device);
			put_ldev(device);
		} else {
			reply->max_possible_size = DRBD_MAX_SECTORS;
			reply->diskful_primary_nodes = 0;
		}
		resource->twopc_resize.dds_flags = be16_to_cpu(p->dds_flags);
		resource->twopc_resize.user_size = be64_to_cpu(p->user_size);
	}

	resource->twopc_reply = *reply;
	spin_unlock_irq(&resource->req_lock);

	switch(pi->cmd) {
	case P_TWOPC_PREPARE:
		drbd_info(connection, "Preparing remote state change %u\n", reply->tid);
		flags |= CS_PREPARE;
		break;
	case P_TWOPC_PREP_RSZ:
		drbd_info(connection, "Preparing remote state change %u "
			  "(local_max_size = %llu KiB)\n",
			  reply->tid, (unsigned long long)reply->max_possible_size >> 1);
		flags |= CS_PREPARE;
		break;
	case P_TWOPC_ABORT:
		drbd_info(connection, "Aborting remote state change %u\n",
			  reply->tid);
		flags |= CS_ABORT;
		break;
	case P_TWOPC_COMMIT:
		drbd_info(connection, "Committing remote state change %u (primary_nodes=%llX)\n",
			  reply->tid, be64_to_cpu(p->primary_nodes));
		break;
	default:
		BUG();
	}

	switch (resource->twopc_type) {
	case TWOPC_STATE_CHANGE:
		if (flags & CS_PREPARED)
			reply->primary_nodes = be64_to_cpu(p->primary_nodes);

		if (peer_device)
			rv = change_peer_device_state(peer_device, mask, val, flags);
		else if (affected_connection)
			rv = change_connection_state(affected_connection,
						     mask, val, reply, flags | CS_IGN_OUTD_FAIL);
		else
			rv = far_away_change(connection, mask, val, reply, flags);
		break;
	case TWOPC_RESIZE:
		if (flags & CS_PREPARE)
			rv = drbd_support_2pc_resize(resource);
		break;
	}

	if (flags & CS_PREPARE) {
		spin_lock_irq(&resource->req_lock);
		kref_get(&connection->kref);
		kref_debug_get(&connection->kref_debug, 9);
		list_add(&connection->twopc_parent_list, &resource->twopc_parents);
		mod_timer(&resource->twopc_timer, receive_jif + twopc_timeout(resource));
		spin_unlock_irq(&resource->req_lock);

		/* Retry replies can be sent immediately. Otherwise use the
		 * nested twopc path. This waits for the state handshake to
		 * complete in the case of a twopc for transitioning to
		 * C_CONNECTED. */
		if (rv == SS_IN_TRANSIENT_STATE) {
			resource->twopc_prepare_reply_cmd = P_TWOPC_RETRY;
			drbd_send_twopc_reply(connection, P_TWOPC_RETRY, reply);
		} else {
			resource->twopc_reply.state_change_failed = rv < SS_SUCCESS;
			nested_twopc_request(resource, pi->vnr, pi->cmd, p);
		}
	} else {
		if (flags & CS_PREPARED) {
			if (rv < SS_SUCCESS)
				drbd_err(resource, "FATAL: Local commit of prepared %u failed! \n",
					 reply->tid);

			del_timer(&resource->twopc_timer);
		}

		nested_twopc_request(resource, pi->vnr, pi->cmd, p);

		if (resource->twopc_type == TWOPC_RESIZE && flags & CS_PREPARED && !(flags & CS_ABORT)) {
			struct twopc_resize *tr = &resource->twopc_resize;
			struct drbd_device *device;

			tr->diskful_primary_nodes = be64_to_cpu(p->diskful_primary_nodes);
			tr->new_size = be64_to_cpu(p->exposed_size);
			device = (peer_device ?: conn_peer_device(connection, pi->vnr))->device;

			drbd_commit_size_change(device, NULL, be64_to_cpu(p->nodes_to_reach));
			rv = SS_SUCCESS;
		}

		clear_remote_state_change(resource);

		if (peer_device && rv >= SS_SUCCESS && !(flags & CS_ABORT))
			drbd_md_sync_if_dirty(peer_device->device);

		if (connection->agreed_pro_version < 117 &&
		    rv >= SS_SUCCESS && !(flags & CS_ABORT) &&
		    affected_connection &&
		    mask.conn == conn_MASK && val.conn == C_CONNECTED)
			conn_connect2(connection);
	}

	return 0;
}

void drbd_try_to_get_resynced(struct drbd_device *device)
{
	int best_resync_peer_preference = 0;
	struct drbd_peer_device *best_peer_device = NULL;
	struct drbd_peer_device *peer_device;
	enum sync_strategy best_strategy = UNDETERMINED;

	if (!get_ldev(device))
		return;

	rcu_read_lock();
	for_each_peer_device_rcu(peer_device, device) {
		enum sync_strategy strategy;
		int rule_nr, peer_node_id;
		if (peer_device->disk_state[NOW] == D_UP_TO_DATE) {
			strategy = drbd_uuid_compare(peer_device, &rule_nr, &peer_node_id);
			drbd_info(peer_device, "strategy = %s\n", strategy_descriptor(strategy).name);
			if (strategy_descriptor(strategy).resync_peer_preference > best_resync_peer_preference) {
				best_resync_peer_preference = strategy_descriptor(strategy).resync_peer_preference;
				best_peer_device = peer_device;
				best_strategy = strategy;
			}
		}
	}
	rcu_read_unlock();
	peer_device = best_peer_device;

	if (best_strategy == NO_SYNC) {
		change_disk_state(device, D_UP_TO_DATE, CS_VERBOSE, NULL);
	} else if (peer_device) {
		drbd_resync(peer_device, DISKLESS_PRIMARY);
		drbd_send_uuids(peer_device, UUID_FLAG_RESYNC | UUID_FLAG_DISKLESS_PRIMARY, 0);
	}
	put_ldev(device);
}

static void finish_nested_twopc(struct drbd_connection *connection)
{
	struct drbd_resource *resource = connection->resource;
	struct drbd_peer_device *peer_device;
	int vnr = 0;

	idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
		if (!test_bit(INITIAL_STATE_RECEIVED, &peer_device->flags))
			return;
	}

	set_bit(CONN_HANDSHAKE_READY, &connection->flags);

	wake_up(&resource->state_wait);

	if (!resource->remote_state_change)
		return;

	if (resource->twopc_parent_nodes == 0) /* we are the initiator, no nesting here */
		return;

	if (cluster_wide_reply_ready(resource) && resource->twopc_work.cb == NULL) {
		resource->twopc_work.cb = nested_twopc_work;
		drbd_queue_work(&resource->work, &resource->twopc_work);
	}
}

static int receive_state(struct drbd_connection *connection, struct packet_info *pi)
{
	struct drbd_resource *resource = connection->resource;
	struct drbd_peer_device *peer_device = NULL;
	enum drbd_repl_state *repl_state;
	struct drbd_device *device = NULL;
	struct p_state *p = pi->data;
	union drbd_state old_peer_state, peer_state;
	enum drbd_disk_state peer_disk_state, new_disk_state = D_MASK;
	enum drbd_repl_state new_repl_state;
	bool peer_was_resync_target;
	enum chg_state_flags begin_state_chg_flags = CS_VERBOSE;
	int rv;

	if (pi->vnr != -1) {
		peer_device = conn_peer_device(connection, pi->vnr);
		if (!peer_device)
			return config_unknown_volume(connection, pi);
		device = peer_device->device;
	}

	peer_state.i = be32_to_cpu(p->state);

	if (connection->agreed_pro_version < 110) {
		/* Before drbd-9.0 there was no D_DETACHING it was D_FAILED... */
		if (peer_state.disk >= D_DETACHING)
			peer_state.disk++;
		if (peer_state.pdsk >= D_DETACHING)
			peer_state.pdsk++;
	}

	if (pi->vnr == -1) {
		if (peer_state.role == R_SECONDARY) {
			unsigned long irq_flags;

			begin_state_change(resource, &irq_flags, CS_HARD | CS_VERBOSE);
			__change_peer_role(connection, R_SECONDARY);
			rv = end_state_change(resource, &irq_flags);
			if (rv < SS_SUCCESS)
				goto fail;
		}
		return 0;
        }

	peer_disk_state = peer_state.disk;

	if (peer_disk_state > D_DISKLESS && !want_bitmap(peer_device)) {
		drbd_warn(peer_device, "The peer is configured to be diskless but presents %s\n",
			  drbd_disk_str(peer_disk_state));
		goto fail;
	}

	if (peer_state.disk == D_NEGOTIATING) {
		peer_disk_state = peer_device->uuid_flags & UUID_FLAG_INCONSISTENT ?
			D_INCONSISTENT : D_CONSISTENT;
		drbd_info(peer_device, "real peer disk state = %s\n", drbd_disk_str(peer_disk_state));
	}

	spin_lock_irq(&resource->req_lock);
	old_peer_state = drbd_get_peer_device_state(peer_device, NOW);
	spin_unlock_irq(&resource->req_lock);
 retry:
	new_repl_state = max_t(enum drbd_repl_state, old_peer_state.conn, L_OFF);

	/* If some other part of the code (ack_receiver thread, timeout)
	 * already decided to close the connection again,
	 * we must not "re-establish" it here. */
	if (old_peer_state.conn <= C_TEAR_DOWN)
		return -ECONNRESET;

	if (!test_bit(INITIAL_STATE_RECEIVED, &peer_device->flags) &&
	    peer_state.role == R_PRIMARY && peer_device->uuid_flags & UUID_FLAG_STABLE)
		check_resync_source(device, peer_device->uuid_node_mask);

	peer_was_resync_target =
		connection->agreed_pro_version >= 110 ?
		peer_device->last_repl_state == L_SYNC_TARGET ||
		peer_device->last_repl_state == L_PAUSED_SYNC_T
		:
		true;
	/* If this is the "end of sync" confirmation, usually the peer disk
	 * was D_INCONSISTENT or D_CONSISTENT. (Since the peer might be
	 * weak we do not know anything about its new disk state)
	 */
	if (peer_was_resync_target &&
	    (old_peer_state.pdsk == D_INCONSISTENT || old_peer_state.pdsk == D_CONSISTENT) &&
	    old_peer_state.conn > L_ESTABLISHED && old_peer_state.disk >= D_INCONSISTENT) {
		/* If we are (becoming) SyncSource, but peer is still in sync
		 * preparation, ignore its uptodate-ness to avoid flapping, it
		 * will change to inconsistent once the peer reaches active
		 * syncing states.
		 * It may have changed syncer-paused flags, however, so we
		 * cannot ignore this completely. */
		if (peer_state.conn > L_ESTABLISHED &&
		    peer_state.conn < L_SYNC_SOURCE)
			peer_disk_state = D_INCONSISTENT;

		/* if peer_state changes to connected at the same time,
		 * it explicitly notifies us that it finished resync.
		 * Maybe we should finish it up, too? */
		else if (peer_state.conn == L_ESTABLISHED) {
			bool finish_now = false;

			if (old_peer_state.conn == L_WF_BITMAP_S) {
				spin_lock_irq(&resource->req_lock);
				if (peer_device->repl_state[NOW] == L_WF_BITMAP_S)
					peer_device->resync_finished_pdsk = peer_state.disk;
				else if (peer_device->repl_state[NOW] == L_SYNC_SOURCE)
					finish_now = true;
				spin_unlock_irq(&resource->req_lock);
			}

			if (finish_now || old_peer_state.conn == L_SYNC_SOURCE ||
			    old_peer_state.conn == L_PAUSED_SYNC_S) {
				drbd_resync_finished(peer_device, peer_state.disk);
				peer_device->last_repl_state = peer_state.conn;
			}
			return 0;
		}
	}

	/* explicit verify finished notification, stop sector reached. */
	if (old_peer_state.conn == L_VERIFY_T && old_peer_state.disk == D_UP_TO_DATE &&
	    peer_state.conn == L_ESTABLISHED && peer_disk_state == D_UP_TO_DATE) {
		ov_out_of_sync_print(peer_device);
		drbd_resync_finished(peer_device, D_MASK);
		peer_device->last_repl_state = peer_state.conn;
		return 0;
	}

	/* Start resync after AHEAD/BEHIND */
	if (connection->agreed_pro_version >= 110 &&
	    peer_state.conn == L_SYNC_SOURCE && old_peer_state.conn == L_BEHIND) {
		drbd_start_resync(peer_device, L_SYNC_TARGET);
		return 0;
	}

	/* peer says his disk is inconsistent, while we think it is uptodate,
	 * and this happens while the peer still thinks we have a sync going on,
	 * but we think we are already done with the sync.
	 * We ignore this to avoid flapping pdsk.
	 * This should not happen, if the peer is a recent version of drbd. */
	if (old_peer_state.pdsk == D_UP_TO_DATE && peer_disk_state == D_INCONSISTENT &&
	    old_peer_state.conn == L_ESTABLISHED && peer_state.conn > L_SYNC_SOURCE)
		peer_disk_state = D_UP_TO_DATE;

	if (new_repl_state == L_OFF)
		new_repl_state = L_ESTABLISHED;

	if (peer_state.conn == L_AHEAD)
		new_repl_state = L_BEHIND;

	if (peer_device->uuids_received &&
	    peer_state.disk >= D_NEGOTIATING &&
	    get_ldev_if_state(device, D_NEGOTIATING)) {
		bool consider_resync;

		/* clear CONN_DISCARD_MY_DATA so late, to not lose it if peer
		   gets aborted before we are able to do the resync handshake. */
		clear_bit(CONN_DISCARD_MY_DATA, &connection->flags);

		/* if we established a new connection */
		consider_resync = (old_peer_state.conn < L_ESTABLISHED);
		/* if we have both been inconsistent, and the peer has been
		 * forced to be UpToDate with --force */
		consider_resync |= test_bit(CONSIDER_RESYNC, &peer_device->flags);
		/* if we had been plain connected, and the admin requested to
		 * start a sync by "invalidate" or "invalidate-remote" */
		consider_resync |= (old_peer_state.conn == L_ESTABLISHED &&
				    (peer_state.conn == L_STARTING_SYNC_S ||
				     peer_state.conn == L_STARTING_SYNC_T));

		consider_resync |= peer_state.conn == L_WF_BITMAP_T &&
				   peer_device->flags & UUID_FLAG_CRASHED_PRIMARY;

		if (consider_resync) {
			new_repl_state = drbd_sync_handshake(peer_device, peer_state);
		} else if (old_peer_state.conn == L_ESTABLISHED &&
			   (peer_state.disk == D_NEGOTIATING ||
			    old_peer_state.disk == D_NEGOTIATING)) {
			new_repl_state = drbd_attach_handshake(peer_device, peer_disk_state);
			if (new_repl_state == L_ESTABLISHED && device->disk_state[NOW] == D_UP_TO_DATE)
				peer_disk_state = D_UP_TO_DATE;
		}

		put_ldev(device);
		if (new_repl_state == -1) { /* retry connect */
			if (connection->agreed_pro_version >= 118) {
				new_repl_state = L_OFF;
				set_bit(CONN_HANDSHAKE_RETRY, &connection->flags);
			} else {
				return -EIO; /* retry connect */
			}
		} else if (new_repl_state == -2) {
			new_repl_state = L_ESTABLISHED;
			if (device->disk_state[NOW] == D_NEGOTIATING) {
				new_repl_state = L_NEG_NO_RESULT;
			} else if (peer_state.disk == D_NEGOTIATING) {
				if (connection->agreed_pro_version < 110) {
					drbd_err(peer_device, "Disk attach process on the peer node was aborted.\n");
					peer_state.disk = D_DISKLESS;
					peer_disk_state = D_DISKLESS;
				} else {
					/* The peer will decide later and let us know... */
					peer_disk_state = D_NEGOTIATING;
				}
			} else {
				if (test_and_clear_bit(CONN_DRY_RUN, &connection->flags))
					return -EIO;
				if (connection->agreed_pro_version >= 118) {
					new_repl_state = L_OFF;
					set_bit(CONN_HANDSHAKE_DISCONNECT, &connection->flags);
				} else {
					goto fail;
				}
			}
		}

		if (device->disk_state[NOW] == D_NEGOTIATING) {
			begin_state_chg_flags |= CS_FORCE_RECALC;
			peer_device->negotiation_result = new_repl_state;
		}
	}
	/* This is after the point where we did UUID comparison and joined with the
	   diskless case again. Releasing uuid_sem here */
	if (test_and_clear_bit(HOLDING_UUID_READ_LOCK, &peer_device->flags)) {
		struct drbd_transport *transport = &connection->transport;
		up_read_non_owner(&device->uuid_sem);
		/* Last packet of handshake received, disarm receive timeout */
		transport->ops->set_rcvtimeo(transport, DATA_STREAM, MAX_SCHEDULE_TIMEOUT);
	}

	if (new_repl_state == L_ESTABLISHED && peer_disk_state == D_CONSISTENT &&
	    drbd_suspended(device) && peer_device->repl_state[NOW] < L_ESTABLISHED &&
	    test_and_clear_bit(NEW_CUR_UUID, &device->flags)) {
		unsigned long irq_flags;

		/* Do not allow RESEND for a rebooted peer. We can only allow this
		   for temporary network outages! */
		drbd_err(peer_device, "Aborting Connect, can not thaw IO with an only Consistent peer\n");
		tl_walk(connection, CONNECTION_LOST_WHILE_PENDING);
		drbd_uuid_new_current(device, false);
		begin_state_change(resource, &irq_flags, CS_HARD);
		__change_cstate(connection, C_PROTOCOL_ERROR);
		__change_io_susp_user(resource, false);
		end_state_change(resource, &irq_flags);
		return -EIO;
	}

	clear_bit(RS_SOURCE_MISSED_END, &peer_device->flags);
	clear_bit(RS_PEER_MISSED_END, &peer_device->flags);

	if (connection->cstate[NOW] == C_CONNECTING) {
		/* Since protocol 117 state comes before change on the cstate */
		peer_device->connect_state = (union drbd_state)
			{ { .disk = new_disk_state,
			    .conn = new_repl_state,
			    .peer = peer_state.role,
			    .pdsk = peer_disk_state,
			    .peer_isp = peer_state.aftr_isp | peer_state.user_isp } };

		set_bit(INITIAL_STATE_RECEIVED, &peer_device->flags);
		wake_up(&connection->ee_wait);

		finish_nested_twopc(connection);
		return 0;
	}
	set_bit(INITIAL_STATE_RECEIVED, &peer_device->flags);

	spin_lock_irq(&resource->req_lock);
	begin_state_change_locked(resource, begin_state_chg_flags);
	if (old_peer_state.i != drbd_get_peer_device_state(peer_device, NOW).i) {
		old_peer_state = drbd_get_peer_device_state(peer_device, NOW);
		abort_state_change_locked(resource);
		spin_unlock_irq(&resource->req_lock);
		goto retry;
	}
	clear_bit(CONSIDER_RESYNC, &peer_device->flags);
	if (new_disk_state != D_MASK)
		__change_disk_state(device, new_disk_state);
	if (device->disk_state[NOW] != D_NEGOTIATING)
		__change_repl_state(peer_device, new_repl_state);
	if (connection->peer_role[NOW] == R_UNKNOWN || peer_state.role == R_SECONDARY)
		__change_peer_role(connection, peer_state.role);
	if (peer_state.disk != D_NEGOTIATING)
		__change_peer_disk_state(peer_device, peer_disk_state);
	__change_resync_susp_peer(peer_device, peer_state.aftr_isp | peer_state.user_isp);
	repl_state = peer_device->repl_state;
	if (repl_state[OLD] < L_ESTABLISHED && repl_state[NEW] >= L_ESTABLISHED)
		resource->state_change_flags |= CS_HARD;

	rv = end_state_change_locked(resource);
	new_repl_state = peer_device->repl_state[NOW];
	set_bit(INITIAL_STATE_PROCESSED, &peer_device->flags); /* Only relevant for agreed_pro_version < 117 */
	spin_unlock_irq(&resource->req_lock);

	if (rv < SS_SUCCESS)
		goto fail;

	if (old_peer_state.conn > L_OFF) {
		if (new_repl_state > L_ESTABLISHED && peer_state.conn <= L_ESTABLISHED &&
		    peer_state.disk != D_NEGOTIATING ) {
			/* we want resync, peer has not yet decided to sync... */
			/* Nowadays only used when forcing a node into primary role and
			   setting its disk to UpToDate with that */
			drbd_send_uuids(peer_device, 0, 0);
			drbd_send_current_state(peer_device);
		}
	}

	clear_bit(DISCARD_MY_DATA, &peer_device->flags); /* Only relevant for agreed_pro_version < 117 */

	drbd_md_sync(device); /* update connected indicator, effective_size, ... */

	peer_device->last_repl_state = peer_state.conn;
	return 0;
fail:
	change_cstate(connection, C_DISCONNECTING, CS_HARD);
	return -EIO;
}

static int receive_sync_uuid(struct drbd_connection *connection, struct packet_info *pi)
{
	struct drbd_peer_device *peer_device;
	struct drbd_device *device;
	struct p_uuid *p = pi->data;

	peer_device = conn_peer_device(connection, pi->vnr);
	if (!peer_device)
		return -EIO;
	device = peer_device->device;

	wait_event(device->misc_wait,
		   peer_device->repl_state[NOW] == L_WF_SYNC_UUID ||
		   peer_device->repl_state[NOW] == L_BEHIND ||
		   peer_device->repl_state[NOW] < L_ESTABLISHED ||
		   device->disk_state[NOW] < D_NEGOTIATING);

	/* D_ASSERT(device,  peer_device->repl_state[NOW] == L_WF_SYNC_UUID ); */

	/* Here the _drbd_uuid_ functions are right, current should
	   _not_ be rotated into the history */
	if (get_ldev_if_state(device, D_NEGOTIATING)) {
		_drbd_uuid_set_current(device, be64_to_cpu(p->uuid));
		_drbd_uuid_set_bitmap(peer_device, 0UL);

		drbd_print_uuids(peer_device, "updated sync uuid");
		drbd_start_resync(peer_device, L_SYNC_TARGET);

		put_ldev(device);
	} else
		drbd_err(device, "Ignoring SyncUUID packet!\n");

	return 0;
}

/**
 * receive_bitmap_plain
 *
 * Return 0 when done, 1 when another iteration is needed, and a negative error
 * code upon failure.
 */
static int
receive_bitmap_plain(struct drbd_peer_device *peer_device, unsigned int size,
		     struct bm_xfer_ctx *c)
{
	unsigned long *p;
	unsigned int data_size = DRBD_SOCKET_BUFFER_SIZE -
				 drbd_header_size(peer_device->connection);
	unsigned int num_words = min_t(size_t, data_size / sizeof(*p),
				       c->bm_words - c->word_offset);
	unsigned int want = num_words * sizeof(*p);
	int err;

	if (want != size) {
		drbd_err(peer_device, "%s:want (%u) != size (%u)\n", __func__, want, size);
		return -EIO;
	}
	if (want == 0)
		return 0;
	err = drbd_recv_all(peer_device->connection, (void **)&p, want);
	if (err)
		return err;

	drbd_bm_merge_lel(peer_device, c->word_offset, num_words, p);

	c->word_offset += num_words;
	c->bit_offset = c->word_offset * BITS_PER_LONG;
	if (c->bit_offset > c->bm_bits)
		c->bit_offset = c->bm_bits;

	return 1;
}

static enum drbd_bitmap_code dcbp_get_code(struct p_compressed_bm *p)
{
	return (enum drbd_bitmap_code)(p->encoding & 0x0f);
}

static int dcbp_get_start(struct p_compressed_bm *p)
{
	return (p->encoding & 0x80) != 0;
}

static int dcbp_get_pad_bits(struct p_compressed_bm *p)
{
	return (p->encoding >> 4) & 0x7;
}

/**
 * recv_bm_rle_bits
 *
 * Return 0 when done, 1 when another iteration is needed, and a negative error
 * code upon failure.
 */
static int
recv_bm_rle_bits(struct drbd_peer_device *peer_device,
		struct p_compressed_bm *p,
		 struct bm_xfer_ctx *c,
		 unsigned int len)
{
	struct bitstream bs;
	u64 look_ahead;
	u64 rl;
	u64 tmp;
	unsigned long s = c->bit_offset;
	unsigned long e;
	int toggle = dcbp_get_start(p);
	int have;
	int bits;

	bitstream_init(&bs, p->code, len, dcbp_get_pad_bits(p));

	bits = bitstream_get_bits(&bs, &look_ahead, 64);
	if (bits < 0)
		return -EIO;

	for (have = bits; have > 0; s += rl, toggle = !toggle) {
		bits = vli_decode_bits(&rl, look_ahead);
		if (bits <= 0)
			return -EIO;

		if (toggle) {
			e = s + rl -1;
			if (e >= c->bm_bits) {
				drbd_err(peer_device, "bitmap overflow (e:%lu) while decoding bm RLE packet\n", e);
				return -EIO;
			}
			drbd_bm_set_many_bits(peer_device, s, e);
		}

		if (have < bits) {
			drbd_err(peer_device, "bitmap decoding error: h:%d b:%d la:0x%08llx l:%u/%u\n",
				have, bits, look_ahead,
				(unsigned int)(bs.cur.b - p->code),
				(unsigned int)bs.buf_len);
			return -EIO;
		}
		/* if we consumed all 64 bits, assign 0; >> 64 is "undefined"; */
		if (likely(bits < 64))
			look_ahead >>= bits;
		else
			look_ahead = 0;
		have -= bits;

		bits = bitstream_get_bits(&bs, &tmp, 64 - have);
		if (bits < 0)
			return -EIO;
		look_ahead |= tmp << have;
		have += bits;
	}

	c->bit_offset = s;
	bm_xfer_ctx_bit_to_word_offset(c);

	return (s != c->bm_bits);
}

/**
 * decode_bitmap_c
 *
 * Return 0 when done, 1 when another iteration is needed, and a negative error
 * code upon failure.
 */
static int
decode_bitmap_c(struct drbd_peer_device *peer_device,
		struct p_compressed_bm *p,
		struct bm_xfer_ctx *c,
		unsigned int len)
{
	if (dcbp_get_code(p) == RLE_VLI_Bits)
		return recv_bm_rle_bits(peer_device, p, c, len - sizeof(*p));

	/* other variants had been implemented for evaluation,
	 * but have been dropped as this one turned out to be "best"
	 * during all our tests. */

	drbd_err(peer_device, "receive_bitmap_c: unknown encoding %u\n", p->encoding);
	change_cstate(peer_device->connection, C_PROTOCOL_ERROR, CS_HARD);
	return -EIO;
}

void INFO_bm_xfer_stats(struct drbd_peer_device *peer_device,
		const char *direction, struct bm_xfer_ctx *c)
{
	/* what would it take to transfer it "plaintext" */
	unsigned int header_size = drbd_header_size(peer_device->connection);
	unsigned int data_size = DRBD_SOCKET_BUFFER_SIZE - header_size;
	unsigned int plain =
		header_size * (DIV_ROUND_UP(c->bm_words, data_size) + 1) +
		c->bm_words * sizeof(unsigned long);
	unsigned int total = c->bytes[0] + c->bytes[1];
	unsigned int r;

	/* total can not be zero. but just in case: */
	if (total == 0)
		return;

	/* don't report if not compressed */
	if (total >= plain)
		return;

	/* total < plain. check for overflow, still */
	r = (total > UINT_MAX/1000) ? (total / (plain/1000))
		                    : (1000 * total / plain);

	if (r > 1000)
		r = 1000;

	r = 1000 - r;
	drbd_info(peer_device, "%s bitmap stats [Bytes(packets)]: plain %u(%u), RLE %u(%u), "
	     "total %u; compression: %u.%u%%\n",
			direction,
			c->bytes[1], c->packets[1],
			c->bytes[0], c->packets[0],
			total, r/10, r % 10);
}

static bool ready_for_bitmap(struct drbd_device *device)
{
	struct drbd_resource *resource = device->resource;
	bool ready = true;

	spin_lock_irq(&resource->req_lock);
	if (device->disk_state[NOW] == D_NEGOTIATING)
		ready = false;
	if (test_bit(TWOPC_STATE_CHANGE_PENDING, &resource->flags))
		ready = false;
	spin_unlock_irq(&resource->req_lock);

	return ready;
}

/* Since we are processing the bitfield from lower addresses to higher,
   it does not matter if the process it in 32 bit chunks or 64 bit
   chunks as long as it is little endian. (Understand it as byte stream,
   beginning with the lowest byte...) If we would use big endian
   we would need to process it from the highest address to the lowest,
   in order to be agnostic to the 32 vs 64 bits issue.

   returns 0 on failure, 1 if we successfully received it. */
static int receive_bitmap(struct drbd_connection *connection, struct packet_info *pi)
{
	struct drbd_peer_device *peer_device;
	enum drbd_repl_state repl_state;
	struct drbd_device *device;
	struct bm_xfer_ctx c;
	int err;

	peer_device = conn_peer_device(connection, pi->vnr);
	if (!peer_device)
		return -EIO;
	if (peer_device->bitmap_index == -1) {
		drbd_err(peer_device, "No bitmap allocated in receive_bitmap()!\n");
		return -EIO;
	}
	device = peer_device->device;

	/* Final repl_states become visible when the disk leaves NEGOTIATING state */
	wait_event_interruptible(device->resource->state_wait,
				 ready_for_bitmap(device));

	drbd_bm_slot_lock(peer_device, "receive bitmap", BM_LOCK_CLEAR | BM_LOCK_BULK);
	/* you are supposed to send additional out-of-sync information
	 * if you actually set bits during this phase */

	c = (struct bm_xfer_ctx) {
		.bm_bits = drbd_bm_bits(device),
		.bm_words = drbd_bm_words(device),
	};

	for(;;) {
		if (pi->cmd == P_BITMAP)
			err = receive_bitmap_plain(peer_device, pi->size, &c);
		else if (pi->cmd == P_COMPRESSED_BITMAP) {
			/* MAYBE: sanity check that we speak proto >= 90,
			 * and the feature is enabled! */
			struct p_compressed_bm *p;

			if (pi->size > DRBD_SOCKET_BUFFER_SIZE - drbd_header_size(connection)) {
				drbd_err(device, "ReportCBitmap packet too large\n");
				err = -EIO;
				goto out;
			}
			if (pi->size <= sizeof(*p)) {
				drbd_err(device, "ReportCBitmap packet too small (l:%u)\n", pi->size);
				err = -EIO;
				goto out;
			}
			err = drbd_recv_all(connection, (void **)&p, pi->size);
			if (err)
			       goto out;
			err = decode_bitmap_c(peer_device, p, &c, pi->size);
		} else {
			drbd_warn(device, "receive_bitmap: cmd neither ReportBitMap nor ReportCBitMap (is 0x%x)", pi->cmd);
			err = -EIO;
			goto out;
		}

		c.packets[pi->cmd == P_BITMAP]++;
		c.bytes[pi->cmd == P_BITMAP] += drbd_header_size(connection) + pi->size;

		if (err <= 0) {
			if (err < 0)
				goto out;
			break;
		}
		err = drbd_recv_header(connection, pi);
		if (err)
			goto out;
	}

	INFO_bm_xfer_stats(peer_device, "receive", &c);

	repl_state = peer_device->repl_state[NOW];
	if (repl_state == L_WF_BITMAP_T) {
		err = drbd_send_bitmap(device, peer_device);
		if (err)
			goto out;
	}

	drbd_bm_slot_unlock(peer_device);

	if (repl_state == L_WF_BITMAP_S) {
		drbd_start_resync(peer_device, L_SYNC_SOURCE);
	} else if (repl_state == L_WF_BITMAP_T) {
		if (connection->agreed_pro_version < 110) {
			enum drbd_state_rv rv;

			/* Omit CS_WAIT_COMPLETE and CS_SERIALIZE with this state
			 * transition to avoid deadlocks. */
			rv = stable_change_repl_state(peer_device, L_WF_SYNC_UUID, CS_VERBOSE);
			D_ASSERT(device, rv == SS_SUCCESS);
		} else {
			drbd_start_resync(peer_device, L_SYNC_TARGET);
		}
	} else {
		/* admin may have requested C_DISCONNECTING,
		 * other threads may have noticed network errors */
		drbd_info(peer_device, "unexpected repl_state (%s) in receive_bitmap\n",
			  drbd_repl_str(repl_state));
	}

	return 0;
 out:
	drbd_bm_slot_unlock(peer_device);
	return err;
}

static int receive_skip(struct drbd_connection *connection, struct packet_info *pi)
{
	drbd_warn(connection, "skipping unknown optional packet type %d, l: %d!\n",
		 pi->cmd, pi->size);

	return ignore_remaining_packet(connection, pi->size);
}

static int receive_UnplugRemote(struct drbd_connection *connection, struct packet_info *pi)
{
	struct drbd_transport *transport = &connection->transport;

	/* Make sure we've acked all the data associated
	 * with the data requests being unplugged */
	transport->ops->hint(transport, DATA_STREAM, QUICKACK);

	/* just unplug all devices always, regardless which volume number */
	drbd_unplug_all_devices(connection);

	return 0;
}

static int receive_out_of_sync(struct drbd_connection *connection, struct packet_info *pi)
{
	struct drbd_peer_device *peer_device;
	struct drbd_device *device;
	struct p_block_desc *p = pi->data;
	sector_t sector;

	peer_device = conn_peer_device(connection, pi->vnr);
	if (!peer_device)
		return -EIO;
	device = peer_device->device;

	sector = be64_to_cpu(p->sector);

	/* see also process_one_request(), before drbd_send_out_of_sync().
	 * Make sure any pending write requests that potentially may
	 * set in-sync have drained, before setting it out-of-sync.
	 * That should be implicit, because of the "epoch" and P_BARRIER logic,
	 * But let's just double-check.
	 */
	conn_wait_active_ee_empty_or_disconnect(connection);
	conn_wait_done_ee_empty_or_disconnect(connection);

	mutex_lock(&peer_device->resync_next_bit_mutex);

	if (peer_device->repl_state[NOW] == L_SYNC_TARGET) {
		unsigned long bit = BM_SECT_TO_BIT(sector);
		if (bit < peer_device->resync_next_bit)
			peer_device->resync_next_bit = bit;
	}

	drbd_set_out_of_sync(peer_device, sector, be32_to_cpu(p->blksize));

	mutex_unlock(&peer_device->resync_next_bit_mutex);

	return 0;
}

static int receive_dagtag(struct drbd_connection *connection, struct packet_info *pi)
{
	struct p_dagtag *p = pi->data;

	connection->last_dagtag_sector = be64_to_cpu(p->dagtag);
	return 0;
}

struct drbd_connection *drbd_connection_by_node_id(struct drbd_resource *resource, int node_id)
{
	/* Caller needs to hold rcu_read_lock(), conf_update */
	struct drbd_connection *connection;

	for_each_connection_rcu(connection, resource) {
		if (connection->peer_node_id == node_id)
			return connection;
	}

	return NULL;
}

struct drbd_connection *drbd_get_connection_by_node_id(struct drbd_resource *resource, int node_id)
{
	struct drbd_connection *connection;

	rcu_read_lock();
	connection = drbd_connection_by_node_id(resource, node_id);
	if (connection)
		kref_get(&connection->kref);
	rcu_read_unlock();

	return connection;
}

static int receive_peer_dagtag(struct drbd_connection *connection, struct packet_info *pi)
{
	struct drbd_resource *resource = connection->resource;
	struct drbd_peer_device *peer_device;
	enum drbd_repl_state new_repl_state;
	struct p_peer_dagtag *p = pi->data;
	struct drbd_connection *lost_peer;
	enum sync_strategy strategy = NO_SYNC;
	s64 dagtag_offset;
	int vnr = 0;

	lost_peer = drbd_get_connection_by_node_id(resource, be32_to_cpu(p->node_id));
	if (!lost_peer)
		return 0;

	kref_debug_get(&lost_peer->kref_debug, 12);

	if (lost_peer->cstate[NOW] == C_CONNECTED) {
		drbd_ping_peer(lost_peer);
		if (lost_peer->cstate[NOW] == C_CONNECTED)
			goto out;
	}

	idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
		enum sync_strategy ps;
		int rule_nr, unused;

		if (peer_device->repl_state[NOW] > L_ESTABLISHED)
			goto out;
		if (!get_ldev(peer_device->device))
			continue;
		ps = drbd_uuid_compare(peer_device, &rule_nr, &unused);
		put_ldev(peer_device->device);

		if (strategy == NO_SYNC) {
			strategy = ps;
			if (strategy != NO_SYNC &&
			    strategy != SYNC_SOURCE_USE_BITMAP &&
			    strategy != SYNC_TARGET_USE_BITMAP) {
				drbd_info(peer_device,
					  "receive_peer_dagatg(): %s by rule %d\n",
					  strategy_descriptor(strategy).name, rule_nr);
				goto out;
			}
		} else if (ps != strategy) {
			drbd_err(peer_device,
				 "receive_peer_dagatg(): Inconsistent resync directions %s %s\n",
				 strategy_descriptor(strategy).name, strategy_descriptor(ps).name);
			goto out;
		}
	}

	/* Need to wait until the other receiver thread has called the
	   cleanup_unacked_peer_requests() function */
	wait_event(resource->state_wait,
		   lost_peer->cstate[NOW] <= C_UNCONNECTED || lost_peer->cstate[NOW] == C_CONNECTING);

	dagtag_offset = (s64)lost_peer->last_dagtag_sector - (s64)be64_to_cpu(p->dagtag);
	if (strategy == SYNC_SOURCE_USE_BITMAP)  {
		new_repl_state = L_WF_BITMAP_S;
	} else if (strategy == SYNC_TARGET_USE_BITMAP)  {
		new_repl_state = L_WF_BITMAP_T;
	} else {
		if (dagtag_offset > 0)
			new_repl_state = L_WF_BITMAP_S;
		else if (dagtag_offset < 0)
			new_repl_state = L_WF_BITMAP_T;
		else
			new_repl_state = L_ESTABLISHED;
	}

	if (new_repl_state != L_ESTABLISHED) {
		unsigned long irq_flags;
		enum drbd_state_rv rv;

		if (new_repl_state == L_WF_BITMAP_T) {
			connection->after_reconciliation.dagtag_sector = be64_to_cpu(p->dagtag);
			connection->after_reconciliation.lost_node_id = be32_to_cpu(p->node_id);
		}

		begin_state_change(resource, &irq_flags, CS_VERBOSE);
		idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
			__change_repl_state(peer_device, new_repl_state);
			set_bit(RECONCILIATION_RESYNC, &peer_device->flags);
		}
		rv = end_state_change(resource, &irq_flags);
		if (rv == SS_SUCCESS)
			drbd_info(connection, "Reconciliation resync because \'%s\' disappeared. (o=%d)\n",
				  lost_peer->transport.net_conf->name, (int)dagtag_offset);
		else if (rv == SS_NOTHING_TO_DO)
			drbd_info(connection, "\'%s\' disappeared (o=%d), no reconciliation since one diskless\n",
				  lost_peer->transport.net_conf->name, (int)dagtag_offset);
			/* sanitize_state() silently removes the resync and the RECONCILIATION_RESYNC bit */
		else
			drbd_info(connection, "rv = %d", rv);
	} else {
		drbd_info(connection, "No reconciliation resync even though \'%s\' disappeared. (o=%d)\n",
			  lost_peer->transport.net_conf->name, (int)dagtag_offset);

		idr_for_each_entry(&connection->peer_devices, peer_device, vnr)
			drbd_bm_clear_many_bits(peer_device, 0, -1UL);
	}

out:
	kref_debug_put(&lost_peer->kref_debug, 12);
	kref_put(&lost_peer->kref, drbd_destroy_connection);
	return 0;
}

/* Accept a new current UUID generated on a diskless node, that just became primary
   (or during handshake) */
static int receive_current_uuid(struct drbd_connection *connection, struct packet_info *pi)
{
	struct drbd_resource *resource = connection->resource;
	struct drbd_peer_device *peer_device;
	struct drbd_device *device;
	struct p_current_uuid *p = pi->data;
	u64 current_uuid, weak_nodes;

	peer_device = conn_peer_device(connection, pi->vnr);
	if (!peer_device)
		return config_unknown_volume(connection, pi);
	device = peer_device->device;

	current_uuid = be64_to_cpu(p->uuid);
	weak_nodes = be64_to_cpu(p->weak_nodes);
	weak_nodes |= NODE_MASK(peer_device->node_id);
	peer_device->current_uuid = current_uuid;

	if (test_bit(INITIAL_STATE_PROCESSED, &peer_device->flags) &&
	    connection->peer_role[NOW] == R_PRIMARY)
		check_resync_source(device, weak_nodes);

	if (connection->peer_role[NOW] == R_UNKNOWN)
		return 0;

	if (current_uuid == drbd_current_uuid(device))
		return 0;

	if (test_bit(INITIAL_STATE_PROCESSED, &peer_device->flags) &&
	    get_ldev_if_state(device, D_UP_TO_DATE)) {
		if (connection->peer_role[NOW] == R_PRIMARY) {
			drbd_warn(peer_device, "received new current UUID: %016llX "
				  "weak_nodes=%016llX\n", current_uuid, weak_nodes);
			drbd_uuid_received_new_current(peer_device, current_uuid, weak_nodes);
			drbd_md_sync_if_dirty(device);
		}
		put_ldev(device);
	} else if (device->disk_state[NOW] == D_DISKLESS && resource->role[NOW] == R_PRIMARY) {
		drbd_set_exposed_data_uuid(device, peer_device->current_uuid);
	}

	return 0;
}

static int receive_rs_deallocated(struct drbd_connection *connection, struct packet_info *pi)
{
	struct drbd_peer_device *peer_device;
	struct p_block_desc *p = pi->data;
	struct drbd_device *device;
	sector_t sector;
	int size, err = 0;

	peer_device = conn_peer_device(connection, pi->vnr);
	if (!peer_device)
		return -EIO;
	device = peer_device->device;

	sector = be64_to_cpu(p->sector);
	size = be32_to_cpu(p->blksize);

	if (get_ldev(device)) {
		struct drbd_peer_request *peer_req;

		peer_req = drbd_alloc_peer_req(peer_device, GFP_NOIO);
		if (!peer_req) {
			put_ldev(device);
			return -ENOMEM;
		}

		dec_rs_pending(peer_device);

		inc_unacked(peer_device);

		peer_req->i.size = size;
		peer_req->i.sector = sector;
		peer_req->block_id = ID_SYNCER;
		peer_req->w.cb = e_end_resync_block;
		peer_req->opf = REQ_OP_DISCARD;
		peer_req->submit_jif = jiffies;
		peer_req->flags |= EE_TRIM;

		spin_lock_irq(&device->resource->req_lock);
		list_add_tail(&peer_req->w.list, &connection->sync_ee);
		spin_unlock_irq(&device->resource->req_lock);

		atomic_add(pi->size >> 9, &device->rs_sect_ev);
		err = drbd_submit_peer_request(peer_req);

		if (err) {
			drbd_err(device, "discard submit failed, triggering re-connect\n");
			spin_lock_irq(&device->resource->req_lock);
			list_del(&peer_req->w.list);
			spin_unlock_irq(&device->resource->req_lock);

			drbd_free_peer_req(peer_req);
			put_ldev(device);
		}

		/* No put_ldev() here. Gets called in drbd_endio_write_sec_final(),
		   as well as drbd_rs_complete_io() */
	} else {
		if (drbd_ratelimit())
			drbd_err(device, "Cannot discard on local disk.\n");

		drbd_send_ack_ex(peer_device, P_NEG_ACK, sector, size, ID_SYNCER);
	}

	rs_sectors_came_in(peer_device, size);

	return err;
}

static int receive_disconnect(struct drbd_connection *connection, struct packet_info *pi)
{
	change_cstate(connection, C_DISCONNECTING, CS_HARD);
	return 0;
}

struct data_cmd {
	int expect_payload;
	unsigned int pkt_size;
	int (*fn)(struct drbd_connection *, struct packet_info *);
};

static struct data_cmd drbd_cmd_handler[] = {
	[P_DATA]	    = { 1, sizeof(struct p_data), receive_Data },
	[P_DATA_REPLY]	    = { 1, sizeof(struct p_data), receive_DataReply },
	[P_RS_DATA_REPLY]   = { 1, sizeof(struct p_data), receive_RSDataReply } ,
	[P_BARRIER]	    = { 0, sizeof(struct p_barrier), receive_Barrier } ,
	[P_BITMAP]	    = { 1, 0, receive_bitmap } ,
	[P_COMPRESSED_BITMAP] = { 1, 0, receive_bitmap } ,
	[P_UNPLUG_REMOTE]   = { 0, 0, receive_UnplugRemote },
	[P_DATA_REQUEST]    = { 0, sizeof(struct p_block_req), receive_DataRequest },
	[P_RS_DATA_REQUEST] = { 0, sizeof(struct p_block_req), receive_DataRequest },
	[P_SYNC_PARAM]	    = { 1, 0, receive_SyncParam },
	[P_SYNC_PARAM89]    = { 1, 0, receive_SyncParam },
	[P_PROTOCOL]        = { 1, sizeof(struct p_protocol), receive_protocol },
	[P_UUIDS]	    = { 0, sizeof(struct p_uuids), receive_uuids },
	[P_SIZES]	    = { 0, sizeof(struct p_sizes), receive_sizes },
	[P_STATE]	    = { 0, sizeof(struct p_state), receive_state },
	[P_STATE_CHG_REQ]   = { 0, sizeof(struct p_req_state), receive_req_state },
	[P_SYNC_UUID]       = { 0, sizeof(struct p_uuid), receive_sync_uuid },
	[P_OV_REQUEST]      = { 0, sizeof(struct p_block_req), receive_DataRequest },
	[P_OV_REPLY]        = { 1, sizeof(struct p_block_req), receive_DataRequest },
	[P_CSUM_RS_REQUEST] = { 1, sizeof(struct p_block_req), receive_DataRequest },
	[P_RS_THIN_REQ]     = { 0, sizeof(struct p_block_req), receive_DataRequest },
	[P_DELAY_PROBE]     = { 0, sizeof(struct p_delay_probe93), receive_skip },
	[P_OUT_OF_SYNC]     = { 0, sizeof(struct p_block_desc), receive_out_of_sync },
	[P_CONN_ST_CHG_REQ] = { 0, sizeof(struct p_req_state), receive_req_state },
	[P_PROTOCOL_UPDATE] = { 1, sizeof(struct p_protocol), receive_protocol },
	[P_TWOPC_PREPARE] = { 0, sizeof(struct p_twopc_request), receive_twopc },
	[P_TWOPC_PREP_RSZ]  = { 0, sizeof(struct p_twopc_request), receive_twopc },
	[P_TWOPC_ABORT] = { 0, sizeof(struct p_twopc_request), receive_twopc },
	[P_DAGTAG]	    = { 0, sizeof(struct p_dagtag), receive_dagtag },
	[P_UUIDS110]	    = { 1, sizeof(struct p_uuids110), receive_uuids110 },
	[P_PEER_DAGTAG]     = { 0, sizeof(struct p_peer_dagtag), receive_peer_dagtag },
	[P_CURRENT_UUID]    = { 0, sizeof(struct p_current_uuid), receive_current_uuid },
	[P_TWOPC_COMMIT]    = { 0, sizeof(struct p_twopc_request), receive_twopc },
	[P_TRIM]	    = { 0, sizeof(struct p_trim), receive_Data },
	[P_ZEROES]	    = { 0, sizeof(struct p_trim), receive_Data },
	[P_RS_DEALLOCATED]  = { 0, sizeof(struct p_block_desc), receive_rs_deallocated },
	[P_WSAME]	    = { 1, sizeof(struct p_wsame), receive_Data },
	[P_DISCONNECT]      = { 0, 0, receive_disconnect },
};

static void drbdd(struct drbd_connection *connection)
{
	struct packet_info pi;
	size_t shs; /* sub header size */
	int err;

	while (get_t_state(&connection->receiver) == RUNNING) {
		struct data_cmd const *cmd;

		drbd_thread_current_set_cpu(&connection->receiver);
		update_receiver_timing_details(connection, drbd_recv_header_maybe_unplug);
		if (drbd_recv_header_maybe_unplug(connection, &pi))
			goto err_out;

		cmd = &drbd_cmd_handler[pi.cmd];
		if (unlikely(pi.cmd >= ARRAY_SIZE(drbd_cmd_handler) || !cmd->fn)) {
			drbd_err(connection, "Unexpected data packet %s (0x%04x)",
				 drbd_packet_name(pi.cmd), pi.cmd);
			goto err_out;
		}

		shs = cmd->pkt_size;
		if (pi.cmd == P_SIZES && connection->agreed_features & DRBD_FF_WSAME)
			shs += sizeof(struct o_qlim);
		if (pi.size > shs && !cmd->expect_payload) {
			drbd_err(connection, "No payload expected %s l:%d\n",
				 drbd_packet_name(pi.cmd), pi.size);
			goto err_out;
		}
		if (pi.size < shs) {
			drbd_err(connection, "%s: unexpected packet size, expected:%d received:%d\n",
				 drbd_packet_name(pi.cmd), (int)shs, pi.size);
			goto err_out;
		}

		if (shs) {
			update_receiver_timing_details(connection, drbd_recv_all_warn);
			err = drbd_recv_all_warn(connection, &pi.data, shs);
			if (err)
				goto err_out;
			pi.size -= shs;
		}

		update_receiver_timing_details(connection, cmd->fn);
		err = cmd->fn(connection, &pi);
		if (err) {
			drbd_err(connection, "error receiving %s, e: %d l: %d!\n",
				 drbd_packet_name(pi.cmd), err, pi.size);
			goto err_out;
		}
	}
	return;

    err_out:
	change_cstate(connection, C_PROTOCOL_ERROR, CS_HARD);
}

static void cleanup_resync_leftovers(struct drbd_peer_device *peer_device)
{
	/* We do not have data structures that would allow us to
	 * get the rs_pending_cnt down to 0 again.
	 *  * On L_SYNC_TARGET we do not have any data structures describing
	 *    the pending RSDataRequest's we have sent.
	 *  * On L_SYNC_SOURCE there is no data structure that tracks
	 *    the P_RS_DATA_REPLY blocks that we sent to the SyncTarget.
	 *  And no, it is not the sum of the reference counts in the
	 *  resync_LRU. The resync_LRU tracks the whole operation including
	 *  the disk-IO, while the rs_pending_cnt only tracks the blocks
	 *  on the fly. */
	drbd_rs_cancel_all(peer_device);
	peer_device->rs_total = 0;
	peer_device->rs_failed = 0;
	atomic_set(&peer_device->rs_pending_cnt, 0);
	wake_up(&peer_device->device->misc_wait);

	del_timer_sync(&peer_device->resync_timer);
	resync_timer_fn(&peer_device->resync_timer);
	del_timer_sync(&peer_device->start_resync_timer);
}

static void drain_resync_activity(struct drbd_connection *connection)
{
	struct drbd_peer_device *peer_device;
	int vnr;

	/* verify or resync related peer requests are read_ee or sync_ee,
	 * drain them first */

	conn_wait_ee_empty(connection, &connection->read_ee);
	conn_wait_ee_empty(connection, &connection->sync_ee);

	rcu_read_lock();
	idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
		struct drbd_device *device = peer_device->device;

		kref_get(&device->kref);
		rcu_read_unlock();

		cleanup_resync_leftovers(peer_device);

		kref_put(&device->kref, drbd_destroy_device);
		rcu_read_lock();
	}
	rcu_read_unlock();
}

static void peer_device_disconnected(struct drbd_peer_device *peer_device)
{
	struct drbd_device *device = peer_device->device;

	if (test_and_clear_bit(HOLDING_UUID_READ_LOCK, &peer_device->flags))
		up_read_non_owner(&device->uuid_sem);

	clear_bit(INITIAL_STATE_SENT, &peer_device->flags);
	clear_bit(INITIAL_STATE_RECEIVED, &peer_device->flags);
	clear_bit(INITIAL_STATE_PROCESSED, &peer_device->flags);
	clear_bit(HAVE_SIZES, &peer_device->flags);

	/* need to do it again, drbd_finish_peer_reqs() may have populated it
	 * again via drbd_try_clear_on_disk_bm(). */
	drbd_rs_cancel_all(peer_device);

	peer_device->uuids_received = false;

	if (!drbd_suspended(device)) {
		struct drbd_resource *resource = device->resource;

		/* We need to create the new UUID immediately when we finish
		   requests that did not reach the lost peer.
		   But when we lost quorum we are going to finish those
		   requests with error, therefore do not create the new UUID
		   immediately! */
		if (!list_empty(&resource->transfer_log) &&
		    drbd_data_accessible(device, NOW) &&
		    !test_bit(PRIMARY_LOST_QUORUM, &device->flags) &&
		    test_and_clear_bit(NEW_CUR_UUID, &device->flags))
			drbd_check_peers_new_current_uuid(device);

		tl_walk(peer_device->connection, CONNECTION_LOST_WHILE_PENDING);
	}

	drbd_md_sync(device);

	if (get_ldev(device)) {
		drbd_bitmap_io(device, &drbd_bm_write_copy_pages, "write from disconnected",
				BM_LOCK_BULK | BM_LOCK_SINGLE_SLOT, peer_device);
		put_ldev(device);
	}
}

static bool any_connection_up(struct drbd_resource *resource)
{
	struct drbd_connection *connection;
	bool rv = false;

	rcu_read_lock();
	for_each_connection_rcu(connection, resource) {
		struct drbd_transport *transport = &connection->transport;
		enum drbd_conn_state cstate = connection->cstate[NOW];

		if (cstate == C_CONNECTED ||
		    (cstate == C_CONNECTING &&
		     transport->ops->stream_ok(transport, DATA_STREAM) &&
		     transport->ops->stream_ok(transport, CONTROL_STREAM))) {
			rv = true;
			break;
		}
	}
	rcu_read_unlock();

	return rv;
}

static void cleanup_remote_state_change(struct drbd_connection *connection)
{
	struct drbd_resource *resource = connection->resource;
	struct twopc_reply *reply = &resource->twopc_reply;

	spin_lock_irq(&resource->req_lock);
	if (resource->remote_state_change &&
	    (drbd_twopc_between_peer_and_me(connection) || !any_connection_up(resource))) {
		bool remote = reply->initiator_node_id != resource->res_opts.node_id;

		drbd_info(connection, "Aborting %s state change %u commit not possible\n",
			  remote ? "remote" : "local", reply->tid);
		if (remote) {
			__clear_remote_state_change(resource);
		} else {
			enum alt_rv alt_rv = abort_local_transaction(resource, 0);
			if (alt_rv != ALT_LOCKED)
				return;
		}
	}
	spin_unlock_irq(&resource->req_lock);
}

static void conn_disconnect(struct drbd_connection *connection)
{
	struct drbd_resource *resource = connection->resource;
	struct drbd_peer_device *peer_device;
	enum drbd_conn_state oc;
	unsigned long irq_flags;
	int vnr, i;

	clear_bit(CONN_DRY_RUN, &connection->flags);
	clear_bit(CONN_CONGESTED, &connection->flags);

	if (connection->cstate[NOW] == C_STANDALONE)
		return;

	/* We are about to start the cleanup after connection loss.
	 * Make sure drbd_submit_bio knows about that.
	 * Usually we should be in some network failure state already,
	 * but just in case we are not, we fix it up here.
	 */
	change_cstate(connection, C_NETWORK_FAILURE, CS_HARD);

	del_connect_timer(connection);

	/* ack_receiver does not clean up anything. it must not interfere, either */
	drbd_thread_stop(&connection->ack_receiver);
	if (connection->ack_sender) {
		destroy_workqueue(connection->ack_sender);
		connection->ack_sender = NULL;
	}

	/* restart sender thread,
	 * potentially get it out of blocking network operations */
	drbd_thread_restart_nowait(&connection->sender);

	drbd_transport_shutdown(connection, CLOSE_CONNECTION);

	cleanup_remote_state_change(connection);

	drain_resync_activity(connection);

	connection->after_reconciliation.lost_node_id = -1;

	/* Wait for current activity to cease.  This includes waiting for
	 * peer_request queued to the submitter workqueue. */
	conn_wait_ee_empty(connection, &connection->active_ee);

	/* wait for all w_e_end_data_req, w_e_end_rsdata_req, w_send_barrier,
	 * w_make_resync_request etc. which may still be on the worker queue
	 * to be "canceled" */
	drbd_flush_workqueue(&connection->sender_work);

	drbd_finish_peer_reqs(connection);

	/* This second workqueue flush is necessary, since drbd_finish_peer_reqs()
	   might have issued a work again. The one before drbd_finish_peer_reqs() is
	   necessary to reclaim net_ee in drbd_finish_peer_reqs(). */
	drbd_flush_workqueue(&connection->sender_work);

	rcu_read_lock();
	idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
		struct drbd_device *device = peer_device->device;

		kref_get(&device->kref);
		rcu_read_unlock();

		peer_device_disconnected(peer_device);

		kref_put(&device->kref, drbd_destroy_device);
		rcu_read_lock();
	}
	rcu_read_unlock();

	i = drbd_free_peer_reqs(resource, &connection->read_ee, true);
	if (i)
		drbd_info(connection, "read_ee not empty, killed %u entries\n", i);
	i = drbd_free_peer_reqs(resource, &connection->active_ee, true);
	if (i)
		drbd_info(connection, "active_ee not empty, killed %u entries\n", i);
	i = drbd_free_peer_reqs(resource, &connection->sync_ee, true);
	if (i)
		drbd_info(connection, "sync_ee not empty, killed %u entries\n", i);
	i = drbd_free_peer_reqs(resource, &connection->net_ee, true);
	if (i)
		drbd_info(connection, "net_ee not empty, killed %u entries\n", i);

	cleanup_unacked_peer_requests(connection);
	cleanup_peer_ack_list(connection);

	i = atomic_read(&connection->pp_in_use);
	if (i)
		drbd_info(connection, "pp_in_use = %d, expected 0\n", i);
	i = atomic_read(&connection->pp_in_use_by_net);
	if (i)
		drbd_info(connection, "pp_in_use_by_net = %d, expected 0\n", i);

	if (!list_empty(&connection->current_epoch->list))
		drbd_err(connection, "ASSERTION FAILED: connection->current_epoch->list not empty\n");
	/* ok, no more ee's on the fly, it is safe to reset the epoch_size */
	atomic_set(&connection->current_epoch->epoch_size, 0);
	connection->send.seen_any_write_yet = false;

	drbd_info(connection, "Connection closed\n");

	if (resource->role[NOW] == R_PRIMARY && conn_highest_pdsk(connection) >= D_UNKNOWN)
		conn_try_outdate_peer_async(connection);

	drbd_maybe_khelper(NULL, connection, "disconnected");

	begin_state_change(resource, &irq_flags, CS_VERBOSE | CS_LOCAL_ONLY);
	oc = connection->cstate[NOW];
	if (oc >= C_UNCONNECTED) {
		__change_cstate(connection, C_UNCONNECTED);
		/* drbd_receiver() has to be restarted after it returns */
		drbd_thread_restart_nowait(&connection->receiver);
	}
	end_state_change(resource, &irq_flags);

	if (oc == C_DISCONNECTING)
		change_cstate(connection, C_STANDALONE, CS_VERBOSE | CS_HARD | CS_LOCAL_ONLY);
}

/*
 * We support PRO_VERSION_MIN to PRO_VERSION_MAX. The protocol version
 * we can agree on is stored in agreed_pro_version.
 *
 * feature flags and the reserved array should be enough room for future
 * enhancements of the handshake protocol, and possible plugins...
 *
 * for now, they are expected to be zero, but ignored.
 */
static int drbd_send_features(struct drbd_connection *connection)
{
	struct p_connection_features *p;

	p = __conn_prepare_command(connection, sizeof(*p), DATA_STREAM);
	if (!p)
		return -EIO;
	memset(p, 0, sizeof(*p));
	p->protocol_min = cpu_to_be32(drbd_protocol_version_min);
	p->protocol_max = cpu_to_be32(PRO_VERSION_MAX);
	p->sender_node_id = cpu_to_be32(connection->resource->res_opts.node_id);
	p->receiver_node_id = cpu_to_be32(connection->peer_node_id);
	p->feature_flags = cpu_to_be32(PRO_FEATURES);
	return __send_command(connection, -1, P_CONNECTION_FEATURES, DATA_STREAM);
}

/*
 * return values:
 *   1 yes, we have a valid connection
 *   0 oops, did not work out, please try again
 *  -1 peer talks different language,
 *     no point in trying again, please go standalone.
 */
int drbd_do_features(struct drbd_connection *connection)
{
	/* ASSERT current == connection->receiver ... */
	struct drbd_resource *resource = connection->resource;
	struct p_connection_features *p;
	const int expect = sizeof(struct p_connection_features);
	struct packet_info pi;
	int err;

	err = drbd_send_features(connection);
	if (err)
		return 0;

	err = drbd_recv_header(connection, &pi);
	if (err) {
		if (err == -EAGAIN)
			drbd_err(connection, "timeout while waiting for feature packet\n");
		return 0;
	}

	if (pi.cmd != P_CONNECTION_FEATURES) {
		drbd_err(connection, "expected ConnectionFeatures packet, received: %s (0x%04x)\n",
			 drbd_packet_name(pi.cmd), pi.cmd);
		return -1;
	}

	if (pi.size != expect) {
		drbd_err(connection, "expected ConnectionFeatures length: %u, received: %u\n",
		     expect, pi.size);
		return -1;
	}

	err = drbd_recv_all_warn(connection, (void **)&p, expect);
	if (err)
		return 0;

	p->protocol_min = be32_to_cpu(p->protocol_min);
	p->protocol_max = be32_to_cpu(p->protocol_max);
	if (p->protocol_max == 0)
		p->protocol_max = p->protocol_min;

	if (PRO_VERSION_MAX < p->protocol_min ||
	    drbd_protocol_version_min > p->protocol_max) {
		drbd_err(connection, "incompatible DRBD dialects: "
		    "I support %d-%d, peer supports %d-%d\n",
		    drbd_protocol_version_min, PRO_VERSION_MAX,
		    p->protocol_min, p->protocol_max);
		return -1;
	}

	connection->agreed_pro_version = min_t(int, PRO_VERSION_MAX, p->protocol_max);
	connection->agreed_features = PRO_FEATURES & be32_to_cpu(p->feature_flags);

	if (connection->agreed_pro_version < 110) {
		struct drbd_connection *connection2;
		bool multiple = false;

		rcu_read_lock();
		for_each_connection_rcu(connection2, resource) {
			if (connection == connection2)
				continue;
			multiple = true;
		}
		rcu_read_unlock();

		if (multiple) {
			drbd_err(connection, "Peer supports protocols %d-%d, but "
				 "multiple connections are only supported in protocol "
				 "110 and above\n", p->protocol_min, p->protocol_max);
			return -1;
		}
	}

	if (connection->agreed_pro_version >= 110) {
		if (be32_to_cpu(p->sender_node_id) != connection->peer_node_id) {
			drbd_err(connection, "Peer presented a node_id of %d instead of %d\n",
				 be32_to_cpu(p->sender_node_id), connection->peer_node_id);
			return 0;
		}
		if (be32_to_cpu(p->receiver_node_id) != resource->res_opts.node_id) {
			drbd_err(connection, "Peer expects me to have a node_id of %d instead of %d\n",
				 be32_to_cpu(p->receiver_node_id), resource->res_opts.node_id);
			return 0;
		}
	}

	drbd_info(connection, "Handshake to peer %d successful: "
			"Agreed network protocol version %d\n",
			connection->peer_node_id,
			connection->agreed_pro_version);

	drbd_info(connection, "Feature flags enabled on protocol level: 0x%x%s%s%s%s.\n",
		  connection->agreed_features,
		  connection->agreed_features & DRBD_FF_TRIM ? " TRIM" : "",
		  connection->agreed_features & DRBD_FF_THIN_RESYNC ? " THIN_RESYNC" : "",
		  connection->agreed_features & DRBD_FF_WSAME ? " WRITE_SAME" : "",
		  connection->agreed_features & DRBD_FF_WZEROES ? " WRITE_ZEROES" :
		  connection->agreed_features ? "" : " none");

	return 1;
}

#if !defined(CONFIG_CRYPTO_HMAC) && !defined(CONFIG_CRYPTO_HMAC_MODULE)
int drbd_do_auth(struct drbd_connection *connection)
{
	drbd_err(connection, "This kernel was build without CONFIG_CRYPTO_HMAC.\n");
	drbd_err(connection, "You need to disable 'cram-hmac-alg' in drbd.conf.\n");
	return -1;
}
#else
#define CHALLENGE_LEN 64 /* must be multiple of 4 */

/* Return value:
	1 - auth succeeded,
	0 - failed, try again (network error),
	-1 - auth failed, don't try again.
*/

struct auth_challenge {
	char d[CHALLENGE_LEN];
	u32 i;
} __attribute__((packed));

int drbd_do_auth(struct drbd_connection *connection)
{
	struct auth_challenge my_challenge, *peers_ch = NULL;
	void *response;
	char *right_response = NULL;
	unsigned int key_len;
	char secret[SHARED_SECRET_MAX]; /* 64 byte */
	unsigned int resp_size;
	struct shash_desc *desc;
	struct packet_info pi;
	struct net_conf *nc;
	int err, rv, dig_size;
	bool peer_is_drbd_9 = connection->agreed_pro_version >= 110;
	void *packet_body;

	rcu_read_lock();
	nc = rcu_dereference(connection->transport.net_conf);
	key_len = strlen(nc->shared_secret);
	memcpy(secret, nc->shared_secret, key_len);
	rcu_read_unlock();

	desc = kmalloc(sizeof(struct shash_desc) +
		       crypto_shash_descsize(connection->cram_hmac_tfm),
		       GFP_KERNEL);
	if (!desc) {
		rv = -1;
		goto fail;
	}
	desc->tfm = connection->cram_hmac_tfm;

	rv = crypto_shash_setkey(connection->cram_hmac_tfm, (u8 *)secret, key_len);
	if (rv) {
		drbd_err(connection, "crypto_shash_setkey() failed with %d\n", rv);
		rv = -1;
		goto fail;
	}

	get_random_bytes(my_challenge.d, sizeof(my_challenge.d));

	packet_body = __conn_prepare_command(connection, sizeof(my_challenge.d), DATA_STREAM);
	if (!packet_body) {
		rv = 0;
		goto fail;
	}
	memcpy(packet_body, my_challenge.d, sizeof(my_challenge.d));

	rv = !__send_command(connection, -1, P_AUTH_CHALLENGE, DATA_STREAM);
	if (!rv)
		goto fail;

	err = drbd_recv_header(connection, &pi);
	if (err) {
		rv = 0;
		goto fail;
	}

	if (pi.cmd != P_AUTH_CHALLENGE) {
		drbd_err(connection, "expected AuthChallenge packet, received: %s (0x%04x)\n",
			 drbd_packet_name(pi.cmd), pi.cmd);
		rv = -1;
		goto fail;
	}

	if (pi.size != sizeof(peers_ch->d)) {
		drbd_err(connection, "unexpected AuthChallenge payload.\n");
		rv = -1;
		goto fail;
	}

	peers_ch = kmalloc(sizeof(*peers_ch), GFP_NOIO);
	if (peers_ch == NULL) {
		drbd_err(connection, "kmalloc of peers_ch failed\n");
		rv = -1;
		goto fail;
	}

	err = drbd_recv_into(connection, peers_ch->d, sizeof(peers_ch->d));
	if (err) {
		rv = 0;
		goto fail;
	}

	if (!memcmp(my_challenge.d, peers_ch->d, sizeof(my_challenge.d))) {
		drbd_err(connection, "Peer presented the same challenge!\n");
		rv = -1;
		goto fail;
	}

	resp_size = crypto_shash_digestsize(connection->cram_hmac_tfm);
	response = __conn_prepare_command(connection, resp_size, DATA_STREAM);
	if (!response) {
		rv = 0;
		goto fail;
	}

	dig_size = pi.size;
	if (peer_is_drbd_9) {
		peers_ch->i = cpu_to_be32(connection->resource->res_opts.node_id);
		dig_size += sizeof(peers_ch->i);
	}

	rv = crypto_shash_digest(desc, peers_ch->d, dig_size, response);
	if (rv) {
		drbd_err(connection, "crypto_shash_digest() failed with %d\n", rv);
		rv = -1;
		goto fail;
	}

	rv = !__send_command(connection, -1, P_AUTH_RESPONSE, DATA_STREAM);
	if (!rv)
		goto fail;

	err = drbd_recv_header(connection, &pi);
	if (err) {
		rv = 0;
		goto fail;
	}

	if (pi.cmd != P_AUTH_RESPONSE) {
		drbd_err(connection, "expected AuthResponse packet, received: %s (0x%04x)\n",
			 drbd_packet_name(pi.cmd), pi.cmd);
		rv = 0;
		goto fail;
	}

	if (pi.size != resp_size) {
		drbd_err(connection, "expected AuthResponse payload of %u bytes, received %u\n",
				resp_size, pi.size);
		rv = 0;
		goto fail;
	}

	err = drbd_recv_all(connection, &response, resp_size);
	if (err) {
		rv = 0;
		goto fail;
	}

	right_response = kmalloc(resp_size, GFP_NOIO);
	if (right_response == NULL) {
		drbd_err(connection, "kmalloc of right_response failed\n");
		rv = -1;
		goto fail;
	}

	dig_size = sizeof(my_challenge.d);
	if (peer_is_drbd_9) {
		my_challenge.i = cpu_to_be32(connection->peer_node_id);
		dig_size += sizeof(my_challenge.i);
	}

	rv = crypto_shash_digest(desc, my_challenge.d, dig_size, right_response);
	if (rv) {
		drbd_err(connection, "crypto_shash_digest() failed with %d\n", rv);
		rv = -1;
		goto fail;
	}

	rv = !memcmp(response, right_response, resp_size);

	if (rv)
		drbd_info(connection, "Peer authenticated using %d bytes HMAC\n",
		     resp_size);
	else
		rv = -1;

 fail:
	kfree(peers_ch);
	kfree(right_response);
	if (desc) {
		shash_desc_zero(desc);
		kfree(desc);
	}

	return rv;
}
#endif

int drbd_receiver(struct drbd_thread *thi)
{
	struct drbd_connection *connection = thi->connection;

	if (conn_connect(connection)) {
		blk_start_plug(&connection->receiver_plug);
		drbdd(connection);
		blk_finish_plug(&connection->receiver_plug);
	}

	conn_disconnect(connection);
	return 0;
}

/* ********* acknowledge sender ******** */

static int process_peer_ack_list(struct drbd_connection *connection)
{
	struct drbd_resource *resource = connection->resource;
	struct drbd_request *req, *tmp;
	unsigned int idx;
	int err = 0;

	idx = connection->peer_node_id;

	spin_lock_irq(&resource->req_lock);
	req = list_first_entry(&resource->peer_ack_list, struct drbd_request, tl_requests);
	while (&req->tl_requests != &resource->peer_ack_list) {
		if (!(req->net_rq_state[idx] & RQ_PEER_ACK)) {
			req = list_next_entry(req, tl_requests);
			continue;
		}
		req->net_rq_state[idx] &= ~RQ_PEER_ACK;
		spin_unlock_irq(&resource->req_lock);

		err = drbd_send_peer_ack(connection, req);

		spin_lock_irq(&resource->req_lock);
		tmp = list_next_entry(req, tl_requests);
		kref_put(&req->kref, destroy_peer_ack_req);
		if (err)
			break;
		req = tmp;
	}
	spin_unlock_irq(&resource->req_lock);
	return err;
}

static int got_peers_in_sync(struct drbd_connection *connection, struct packet_info *pi)
{
	struct drbd_peer_device *peer_device;
	struct drbd_device *device;
	struct p_peer_block_desc *p = pi->data;
	sector_t sector;
	u64 in_sync_b;
	int size;

	peer_device = conn_peer_device(connection, pi->vnr);
	if (!peer_device)
		return -EIO;

	device = peer_device->device;

	if (get_ldev(device)) {
		sector = be64_to_cpu(p->sector);
		size = be32_to_cpu(p->size);
		in_sync_b = node_ids_to_bitmap(device, be64_to_cpu(p->mask));

		drbd_set_sync(device, sector, size, 0, in_sync_b);
		put_ldev(device);
	}

	return 0;
}

static int got_RqSReply(struct drbd_connection *connection, struct packet_info *pi)
{
	struct p_req_state_reply *p = pi->data;
	int retcode = be32_to_cpu(p->retcode);

	if (retcode >= SS_SUCCESS)
		set_bit(TWOPC_YES, &connection->flags);
	else {
		set_bit(TWOPC_NO, &connection->flags);
		drbd_debug(connection, "Requested state change failed by peer: %s (%d)\n",
			   drbd_set_st_err_str(retcode), retcode);
	}

	wake_up(&connection->resource->state_wait);

	return 0;
}

static int got_twopc_reply(struct drbd_connection *connection, struct packet_info *pi)
{
	struct drbd_resource *resource = connection->resource;
	struct p_twopc_reply *p = pi->data;

	spin_lock_irq(&resource->req_lock);
	if (resource->twopc_reply.initiator_node_id == be32_to_cpu(p->initiator_node_id) &&
	    resource->twopc_reply.tid == be32_to_cpu(p->tid)) {
		drbd_debug(connection, "Got a %s reply for state change %u\n",
			   drbd_packet_name(pi->cmd),
			   resource->twopc_reply.tid);

		if (pi->cmd == P_TWOPC_YES) {
			struct drbd_peer_device *peer_device;
			u64 reachable_nodes;
			u64 max_size;

			switch (resource->twopc_type) {
			case TWOPC_STATE_CHANGE:
				reachable_nodes =
					be64_to_cpu(p->reachable_nodes);

				if (resource->res_opts.node_id ==
				    resource->twopc_reply.initiator_node_id &&
				    connection->peer_node_id ==
				    resource->twopc_reply.target_node_id) {
					resource->twopc_reply.target_reachable_nodes |=
						reachable_nodes;
				} else {
					resource->twopc_reply.reachable_nodes |=
						reachable_nodes;
				}
				resource->twopc_reply.primary_nodes |=
					be64_to_cpu(p->primary_nodes);
				resource->twopc_reply.weak_nodes |=
					be64_to_cpu(p->weak_nodes);
				break;
			case TWOPC_RESIZE:
				resource->twopc_reply.diskful_primary_nodes |=
					be64_to_cpu(p->diskful_primary_nodes);
				max_size = be64_to_cpu(p->max_possible_size);
				resource->twopc_reply.max_possible_size =
					min_t(sector_t, resource->twopc_reply.max_possible_size,
					      max_size);
				peer_device = conn_peer_device(connection, resource->twopc_reply.vnr);
				if (peer_device)
					peer_device->max_size = max_size;
				break;
			}
		}

		if (pi->cmd == P_TWOPC_YES)
			set_bit(TWOPC_YES, &connection->flags);
		else if (pi->cmd == P_TWOPC_NO)
			set_bit(TWOPC_NO, &connection->flags);
		else if (pi->cmd == P_TWOPC_RETRY)
			set_bit(TWOPC_RETRY, &connection->flags);
		if (cluster_wide_reply_ready(resource)) {
			int my_node_id = resource->res_opts.node_id;
			if (resource->twopc_reply.initiator_node_id == my_node_id) {
				wake_up(&resource->state_wait);
			} else if (resource->twopc_work.cb == NULL) {
				/* in case the timeout timer was not quicker in queuing the work... */
				resource->twopc_work.cb = nested_twopc_work;
				drbd_queue_work(&resource->work, &resource->twopc_work);
			}
		}
	} else {
		drbd_debug(connection, "Ignoring %s reply for state change %u\n",
			   drbd_packet_name(pi->cmd),
			   be32_to_cpu(p->tid));
	}
	spin_unlock_irq(&resource->req_lock);

	return 0;
}

void twopc_connection_down(struct drbd_connection *connection)
{
	struct drbd_resource *resource = connection->resource;

	assert_spin_locked(&resource->req_lock);
	if (resource->twopc_reply.initiator_node_id != -1 &&
	    test_bit(TWOPC_PREPARED, &connection->flags)) {
		set_bit(TWOPC_RETRY, &connection->flags);
		if (cluster_wide_reply_ready(resource)) {
			int my_node_id = resource->res_opts.node_id;
			if (resource->twopc_reply.initiator_node_id == my_node_id) {
				wake_up(&resource->state_wait);
			} else if (resource->twopc_work.cb == NULL) {
				/* in case the timeout timer was not quicker in queuing the work... */
				resource->twopc_work.cb = nested_twopc_work;
				drbd_queue_work(&resource->work, &resource->twopc_work);
			}
		}
	}
}

static int got_Ping(struct drbd_connection *connection, struct packet_info *pi)
{
	return drbd_send_ping_ack(connection);

}

static int got_PingAck(struct drbd_connection *connection, struct packet_info *pi)
{
	if (!test_bit(GOT_PING_ACK, &connection->flags)) {
		set_bit(GOT_PING_ACK, &connection->flags);
		wake_up(&connection->resource->state_wait);
	}

	return 0;
}

static int got_IsInSync(struct drbd_connection *connection, struct packet_info *pi)
{
	struct drbd_peer_device *peer_device;
	struct drbd_device *device;
	struct p_block_ack *p = pi->data;
	sector_t sector = be64_to_cpu(p->sector);
	int blksize = be32_to_cpu(p->blksize);

	peer_device = conn_peer_device(connection, pi->vnr);
	if (!peer_device)
		return -EIO;
	device = peer_device->device;

	D_ASSERT(device, connection->agreed_pro_version >= 89);

	update_peer_seq(peer_device, be32_to_cpu(p->seq_num));

	if (get_ldev(device)) {
		drbd_rs_complete_io(peer_device, sector);
		drbd_set_in_sync(peer_device, sector, blksize);
		/* rs_same_csums is supposed to count in units of BM_BLOCK_SIZE */
		peer_device->rs_same_csum += (blksize >> BM_BLOCK_SHIFT);
		put_ldev(device);
	}
	dec_rs_pending(peer_device);
	rs_sectors_came_in(peer_device, blksize);

	return 0;
}

static int
validate_req_change_req_state(struct drbd_peer_device *peer_device, u64 id, sector_t sector,
			      struct rb_root *root, const char *func,
			      enum drbd_req_event what, bool missing_ok)
{
	struct drbd_device *device = peer_device->device;
	struct drbd_request *req;
	struct bio_and_error m;

	spin_lock_irq(&device->resource->req_lock);
	req = find_request(device, root, id, sector, missing_ok, func);
	if (unlikely(!req)) {
		spin_unlock_irq(&device->resource->req_lock);
		return -EIO;
	}
	__req_mod(req, what, peer_device, &m);
	spin_unlock_irq(&device->resource->req_lock);

	if (m.bio)
		complete_master_bio(device, &m);
	return 0;
}

static int got_BlockAck(struct drbd_connection *connection, struct packet_info *pi)
{
	struct drbd_peer_device *peer_device;
	struct drbd_device *device;
	struct p_block_ack *p = pi->data;
	sector_t sector = be64_to_cpu(p->sector);
	int blksize = be32_to_cpu(p->blksize);
	enum drbd_req_event what;

	peer_device = conn_peer_device(connection, pi->vnr);
	if (!peer_device)
		return -EIO;
	device = peer_device->device;

	update_peer_seq(peer_device, be32_to_cpu(p->seq_num));

	if (p->block_id == ID_SYNCER) {
		drbd_set_in_sync(peer_device, sector, blksize);
		dec_rs_pending(peer_device);
		atomic_sub(blksize >> 9, &connection->rs_in_flight);
		return 0;
	}
	switch (pi->cmd) {
	case P_RS_WRITE_ACK:
		what = WRITE_ACKED_BY_PEER_AND_SIS;
		break;
	case P_WRITE_ACK:
		what = WRITE_ACKED_BY_PEER;
		break;
	case P_RECV_ACK:
		what = RECV_ACKED_BY_PEER;
		break;
	case P_SUPERSEDED:
		what = DISCARD_WRITE;
		break;
	case P_RETRY_WRITE:
		what = POSTPONE_WRITE;
		break;
	default:
		BUG();
	}

	return validate_req_change_req_state(peer_device, p->block_id, sector,
					     &device->write_requests, __func__,
					     what, false);
}

static int got_NegAck(struct drbd_connection *connection, struct packet_info *pi)
{
	struct drbd_peer_device *peer_device;
	struct drbd_device *device;
	struct p_block_ack *p = pi->data;
	sector_t sector = be64_to_cpu(p->sector);
	int size = be32_to_cpu(p->blksize);
	int err;

	peer_device = conn_peer_device(connection, pi->vnr);
	if (!peer_device)
		return -EIO;
	device = peer_device->device;

	update_peer_seq(peer_device, be32_to_cpu(p->seq_num));

	if (peer_device->disk_state[NOW] == D_UP_TO_DATE)
		set_bit(GOT_NEG_ACK, &peer_device->flags);

	if (p->block_id == ID_SYNCER) {
		dec_rs_pending(peer_device);
		drbd_rs_failed_io(peer_device, sector, size);
		return 0;
	}

	err = validate_req_change_req_state(peer_device, p->block_id, sector,
					    &device->write_requests, __func__,
					    NEG_ACKED, true);
	if (err) {
		/* Protocol A has no P_WRITE_ACKs, but has P_NEG_ACKs.
		   The master bio might already be completed, therefore the
		   request is no longer in the collision hash. */
		/* In Protocol B we might already have got a P_RECV_ACK
		   but then get a P_NEG_ACK afterwards. */
		drbd_set_out_of_sync(peer_device, sector, size);
	}
	return 0;
}

static int got_NegDReply(struct drbd_connection *connection, struct packet_info *pi)
{
	struct drbd_peer_device *peer_device;
	struct drbd_device *device;
	struct p_block_ack *p = pi->data;
	sector_t sector = be64_to_cpu(p->sector);

	peer_device = conn_peer_device(connection, pi->vnr);
	if (!peer_device)
		return -EIO;
	device = peer_device->device;

	update_peer_seq(peer_device, be32_to_cpu(p->seq_num));

	drbd_err(device, "Got NegDReply; Sector %llus, len %u.\n",
		 (unsigned long long)sector, be32_to_cpu(p->blksize));

	return validate_req_change_req_state(peer_device, p->block_id, sector,
					     &device->read_requests, __func__,
					     NEG_ACKED, false);
}

static int got_NegRSDReply(struct drbd_connection *connection, struct packet_info *pi)
{
	struct drbd_peer_device *peer_device;
	struct drbd_device *device;
	sector_t sector;
	int size;
	struct p_block_ack *p = pi->data;
	unsigned long bit;

	peer_device = conn_peer_device(connection, pi->vnr);
	if (!peer_device)
		return -EIO;
	device = peer_device->device;

	sector = be64_to_cpu(p->sector);
	size = be32_to_cpu(p->blksize);

	update_peer_seq(peer_device, be32_to_cpu(p->seq_num));

	dec_rs_pending(peer_device);

	if (get_ldev_if_state(device, D_DETACHING)) {
		drbd_rs_complete_io(peer_device, sector);
		switch (pi->cmd) {
		case P_NEG_RS_DREPLY:
			drbd_rs_failed_io(peer_device, sector, size);
			break;
		case P_RS_CANCEL_AHEAD:
			set_bit(SYNC_TARGET_TO_BEHIND, &peer_device->flags);
			fallthrough;
		case P_RS_CANCEL:
			if (peer_device->repl_state[NOW] == L_VERIFY_S) {
				verify_skipped_block(peer_device, sector, size);
			} else {
				bit = BM_SECT_TO_BIT(sector);
				mutex_lock(&peer_device->resync_next_bit_mutex);
				peer_device->resync_next_bit = min(peer_device->resync_next_bit, bit);
				mutex_unlock(&peer_device->resync_next_bit_mutex);
			}

			break;
		default:
			BUG();
		}
		rs_sectors_came_in(peer_device, size);
		mod_timer(&peer_device->resync_timer, jiffies + RS_MAKE_REQS_INTV);
		put_ldev(device);
	}

	return 0;
}

static int got_BarrierAck(struct drbd_connection *connection, struct packet_info *pi)
{
	struct p_barrier_ack *p = pi->data;

	tl_release(connection, 0, 0, p->barrier, be32_to_cpu(p->set_size));

	return 0;
}

static int got_confirm_stable(struct drbd_connection *connection, struct packet_info *pi)
{
	struct p_confirm_stable *p = pi->data;

	tl_release(connection, p->oldest_block_id, p->youngest_block_id, 0, be32_to_cpu(p->set_size));

	return 0;
}

static int got_OVResult(struct drbd_connection *connection, struct packet_info *pi)
{
	struct drbd_peer_device *peer_device;
	struct drbd_device *device;
	struct p_block_ack *p = pi->data;
	sector_t sector;
	int size;

	peer_device = conn_peer_device(connection, pi->vnr);
	if (!peer_device)
		return -EIO;
	device = peer_device->device;

	sector = be64_to_cpu(p->sector);
	size = be32_to_cpu(p->blksize);

	update_peer_seq(peer_device, be32_to_cpu(p->seq_num));

	if (be64_to_cpu(p->block_id) == ID_OUT_OF_SYNC)
		drbd_ov_out_of_sync_found(peer_device, sector, size);
	else
		ov_out_of_sync_print(peer_device);

	if (!get_ldev(device))
		return 0;

	drbd_rs_complete_io(peer_device, sector);
	dec_rs_pending(peer_device);

	verify_progress(peer_device, sector, size);

	put_ldev(device);
	return 0;
}

static int got_skip(struct drbd_connection *connection, struct packet_info *pi)
{
	return 0;
}

static u64 node_id_to_mask(struct drbd_peer_md *peer_md, int node_id) __must_hold(local)
{
	int bitmap_bit = peer_md[node_id].bitmap_index;
	return (bitmap_bit >= 0) ? NODE_MASK(bitmap_bit) : 0;
}

static u64 node_ids_to_bitmap(struct drbd_device *device, u64 node_ids) __must_hold(local)
{
	struct drbd_peer_md *peer_md = device->ldev->md.peers;
	u64 bitmap_bits = 0;
	int node_id;

	for_each_set_bit(node_id, (unsigned long *)&node_ids, DRBD_NODE_ID_MAX)
		bitmap_bits |= node_id_to_mask(peer_md, node_id);
	return bitmap_bits;
}


static bool is_sync_source(struct drbd_peer_device *peer_device)
{
	return is_sync_source_state(peer_device, NOW) ||
		peer_device->repl_state[NOW] == L_WF_BITMAP_S;
}

static int w_send_out_of_sync(struct drbd_work *w, int cancel)
{
	struct drbd_peer_request *peer_req =
		container_of(w, struct drbd_peer_request, w);
	struct drbd_peer_device *peer_device = peer_req->send_oos_peer_device;
	struct drbd_device *device = peer_device->device;
	u64 in_sync = peer_req->send_oos_in_sync;
	int err;

	err = drbd_send_out_of_sync(peer_device, peer_req->i.sector, peer_req->i.size);
	peer_req->sent_oos_nodes |= NODE_MASK(peer_device->node_id);

	rcu_read_lock();
	for_each_peer_device_rcu(peer_device, device) {
		if (!(NODE_MASK(peer_device->node_id) & in_sync) &&
		    is_sync_source(peer_device) &&
		    !(peer_req->sent_oos_nodes & NODE_MASK(peer_device->node_id))) {
			rcu_read_unlock();
			peer_req->send_oos_peer_device = peer_device;
			drbd_queue_work(&peer_device->connection->sender_work,
					&peer_req->w);
			return err;
		}
	}
	rcu_read_unlock();
	drbd_free_peer_req(peer_req);

	return err;
}

static void notify_sync_targets_or_free(struct drbd_peer_request *peer_req, u64 in_sync)
{
	struct drbd_device *device = peer_req->peer_device->device;
	struct drbd_peer_device *peer_device;

	rcu_read_lock();
	for_each_peer_device_rcu(peer_device, device) {
		if (!(NODE_MASK(peer_device->node_id) & in_sync) &&
		    is_sync_source(peer_device)) {
			rcu_read_unlock();
			peer_req->sent_oos_nodes = 0;
			peer_req->send_oos_peer_device = peer_device;
			peer_req->send_oos_in_sync = in_sync;
			peer_req->w.cb = w_send_out_of_sync;
			drbd_queue_work(&peer_device->connection->sender_work,
					&peer_req->w);
			return;
		}
	}
	rcu_read_unlock();
	drbd_free_peer_req(peer_req);
}

static int got_peer_ack(struct drbd_connection *connection, struct packet_info *pi)
{
	struct drbd_resource *resource = connection->resource;
	struct p_peer_ack *p = pi->data;
	u64 dagtag, in_sync;
	struct drbd_peer_request *peer_req, *tmp;
	struct list_head work_list;

	dagtag = be64_to_cpu(p->dagtag);
	in_sync = be64_to_cpu(p->mask);

	spin_lock_irq(&resource->req_lock);
	list_for_each_entry(peer_req, &connection->peer_requests, recv_order) {
		if (dagtag == peer_req->dagtag_sector)
			goto found;
	}
	spin_unlock_irq(&resource->req_lock);

	drbd_err(connection, "peer request with dagtag %llu not found\n", dagtag);
	return -EIO;

found:
	list_cut_position(&work_list, &connection->peer_requests, &peer_req->recv_order);
	spin_unlock_irq(&resource->req_lock);

	list_for_each_entry_safe(peer_req, tmp, &work_list, recv_order) {
		struct drbd_peer_device *peer_device = peer_req->peer_device;
		struct drbd_device *device = peer_device->device;
		u64 in_sync_b, mask;

		D_ASSERT(peer_device, peer_req->flags & EE_IN_ACTLOG);

		if (get_ldev(device)) {
			if ((peer_req->flags & EE_WAS_ERROR) == 0)
				in_sync_b = node_ids_to_bitmap(device, in_sync);
			else
				in_sync_b = 0;
			mask = ~node_id_to_mask(device->ldev->md.peers,
						connection->peer_node_id);

			drbd_set_sync(device, peer_req->i.sector,
				      peer_req->i.size, ~in_sync_b, mask);
			drbd_al_complete_io(device, &peer_req->i);
			put_ldev(device);
		}
		list_del(&peer_req->recv_order);
		notify_sync_targets_or_free(peer_req, in_sync);
	}
	return 0;
}

/* Caller has to hold resource->req_lock */
void apply_unacked_peer_requests(struct drbd_connection *connection)
{
	struct drbd_peer_request *peer_req;

	list_for_each_entry(peer_req, &connection->peer_requests, recv_order) {
		struct drbd_peer_device *peer_device = peer_req->peer_device;
		struct drbd_device *device = peer_device->device;
		int bitmap_index = peer_device->bitmap_index;
		u64 mask = ~(bitmap_index != -1 ? 1UL << bitmap_index : 0UL);

		drbd_set_sync(device, peer_req->i.sector, peer_req->i.size,
			      mask, mask);
	}
}

static void cleanup_unacked_peer_requests(struct drbd_connection *connection)
{
	struct drbd_resource *resource = connection->resource;
	struct drbd_peer_request *peer_req, *tmp;
	LIST_HEAD(work_list);

	spin_lock_irq(&resource->req_lock);
	list_splice_init(&connection->peer_requests, &work_list);
	spin_unlock_irq(&resource->req_lock);

	list_for_each_entry_safe(peer_req, tmp, &work_list, recv_order) {
		struct drbd_peer_device *peer_device = peer_req->peer_device;
		struct drbd_device *device = peer_device->device;
		int bitmap_index = peer_device->bitmap_index;
		u64 mask = ~(bitmap_index != -1 ? 1UL << bitmap_index : 0UL);

		if (get_ldev(device)) {
			drbd_set_sync(device, peer_req->i.sector, peer_req->i.size,
				      mask, mask);
			drbd_al_complete_io(device, &peer_req->i);
			put_ldev(device);
		}
		list_del(&peer_req->recv_order);
		notify_sync_targets_or_free(peer_req, 0);
	}
}

static void destroy_peer_ack_req(struct kref *kref)
{
	struct drbd_request *req =
		container_of(kref, struct drbd_request, kref);

	list_del(&req->tl_requests);
	mempool_free(req, &drbd_request_mempool);
}

static void cleanup_peer_ack_list(struct drbd_connection *connection)
{
	struct drbd_resource *resource = connection->resource;
	struct drbd_request *req, *tmp;
	int idx = connection->peer_node_id;

	spin_lock_irq(&resource->req_lock);
	list_for_each_entry_safe(req, tmp, &resource->peer_ack_list, tl_requests) {
		if (!(req->net_rq_state[idx] & RQ_PEER_ACK))
			continue;
		req->net_rq_state[idx] &= ~RQ_PEER_ACK;
		kref_put(&req->kref, destroy_peer_ack_req);
	}
	req = resource->peer_ack_req;
	if (req)
		req->net_rq_state[idx] &= ~RQ_NET_SENT;
	spin_unlock_irq(&resource->req_lock);
}

struct meta_sock_cmd {
	size_t pkt_size;
	int (*fn)(struct drbd_connection *connection, struct packet_info *);
};

static void set_rcvtimeo(struct drbd_connection *connection, bool ping_timeout)
{
	long t;
	struct net_conf *nc;
	struct drbd_transport *transport = &connection->transport;
	struct drbd_transport_ops *tr_ops = transport->ops;


	rcu_read_lock();
	nc = rcu_dereference(transport->net_conf);
	t = ping_timeout ? nc->ping_timeo : nc->ping_int;
	rcu_read_unlock();

	t *= HZ;
	if (ping_timeout)
		t /= 10;

	tr_ops->set_rcvtimeo(transport, CONTROL_STREAM, t);
}

static void set_ping_timeout(struct drbd_connection *connection)
{
	set_rcvtimeo(connection, 1);
}

static void set_idle_timeout(struct drbd_connection *connection)
{
	set_rcvtimeo(connection, 0);
}

static struct meta_sock_cmd ack_receiver_tbl[] = {
	[P_PING]	    = { 0, got_Ping },
	[P_PING_ACK]	    = { 0, got_PingAck },
	[P_RECV_ACK]	    = { sizeof(struct p_block_ack), got_BlockAck },
	[P_WRITE_ACK]	    = { sizeof(struct p_block_ack), got_BlockAck },
	[P_RS_WRITE_ACK]    = { sizeof(struct p_block_ack), got_BlockAck },
	[P_SUPERSEDED]      = { sizeof(struct p_block_ack), got_BlockAck },
	[P_NEG_ACK]	    = { sizeof(struct p_block_ack), got_NegAck },
	[P_NEG_DREPLY]	    = { sizeof(struct p_block_ack), got_NegDReply },
	[P_NEG_RS_DREPLY]   = { sizeof(struct p_block_ack), got_NegRSDReply },
	[P_OV_RESULT]	    = { sizeof(struct p_block_ack), got_OVResult },
	[P_BARRIER_ACK]	    = { sizeof(struct p_barrier_ack), got_BarrierAck },
	[P_CONFIRM_STABLE]  = { sizeof(struct p_confirm_stable), got_confirm_stable },
	[P_STATE_CHG_REPLY] = { sizeof(struct p_req_state_reply), got_RqSReply },
	[P_RS_IS_IN_SYNC]   = { sizeof(struct p_block_ack), got_IsInSync },
	[P_DELAY_PROBE]     = { sizeof(struct p_delay_probe93), got_skip },
	[P_RS_CANCEL]       = { sizeof(struct p_block_ack), got_NegRSDReply },
	[P_RS_CANCEL_AHEAD] = { sizeof(struct p_block_ack), got_NegRSDReply },
	[P_CONN_ST_CHG_REPLY]={ sizeof(struct p_req_state_reply), got_RqSReply },
	[P_RETRY_WRITE]	    = { sizeof(struct p_block_ack), got_BlockAck },
	[P_PEER_ACK]	    = { sizeof(struct p_peer_ack), got_peer_ack },
	[P_PEERS_IN_SYNC]   = { sizeof(struct p_peer_block_desc), got_peers_in_sync },
	[P_TWOPC_YES]       = { sizeof(struct p_twopc_reply), got_twopc_reply },
	[P_TWOPC_NO]        = { sizeof(struct p_twopc_reply), got_twopc_reply },
	[P_TWOPC_RETRY]     = { sizeof(struct p_twopc_reply), got_twopc_reply },
};

int drbd_ack_receiver(struct drbd_thread *thi)
{
	struct drbd_connection *connection = thi->connection;
	struct meta_sock_cmd *cmd = NULL;
	struct packet_info pi;
	unsigned long pre_recv_jif;
	int rv;
	void *buffer;
	int received = 0, rflags = 0;
	unsigned int header_size = drbd_header_size(connection);
	int expect   = header_size;
	bool ping_timeout_active = false;
	struct drbd_transport *transport = &connection->transport;
	struct drbd_transport_ops *tr_ops = transport->ops;

	sched_set_fifo_low(current);

	while (get_t_state(thi) == RUNNING) {
		drbd_thread_current_set_cpu(thi);

		drbd_reclaim_net_peer_reqs(connection);

		if (test_bit(SEND_PING, &connection->flags)) {
			clear_bit(SEND_PING, &connection->flags);
			if (drbd_send_ping(connection)) {
				drbd_err(connection, "drbd_send_ping has failed\n");
				goto reconnect;
			}
			set_ping_timeout(connection);
			ping_timeout_active = true;
		}

		pre_recv_jif = jiffies;
		rv = tr_ops->recv(transport, CONTROL_STREAM, &buffer, expect - received, rflags);

		/* Note:
		 * -EINTR	 (on meta) we got a signal
		 * -EAGAIN	 (on meta) rcvtimeo expired
		 * -ECONNRESET	 other side closed the connection
		 * -ERESTARTSYS  (on data) we got a signal
		 * rv <  0	 other than above: unexpected error!
		 * rv == expected: full header or command
		 * rv <  expected: "woken" by signal during receive
		 * rv == 0	 : "connection shut down by peer"
		 */
		if (likely(rv > 0)) {
			received += rv;

			if (received < expect)
				rflags = GROW_BUFFER;

		} else if (rv == 0) {
			long t;

			rcu_read_lock();
			t = rcu_dereference(connection->transport.net_conf)->ping_timeo * HZ/10;
			rcu_read_unlock();

			t = wait_event_timeout(connection->resource->state_wait,
					       connection->cstate[NOW] < C_CONNECTING,
					       t);
			if (t)
				break;

			drbd_err(connection, "meta connection shut down by peer.\n");
			goto reconnect;
		} else if (rv == -EAGAIN) {
			/* If the data socket received something meanwhile,
			 * that is good enough: peer is still alive. */

			if (time_after(connection->last_received, pre_recv_jif))
				continue;
			if (ping_timeout_active) {
				drbd_err(connection, "PingAck did not arrive in time.\n");
				goto reconnect;
			}
			set_bit(SEND_PING, &connection->flags);
			continue;
		} else if (rv == -EINTR) {
			/* maybe drbd_thread_stop(): the while condition will notice.
			 * maybe woken for send_ping: we'll send a ping above,
			 * and change the rcvtimeo */
			flush_signals(current);
			continue;
		} else {
			drbd_err(connection, "sock_recvmsg returned %d\n", rv);
			goto reconnect;
		}

		if (received == expect && cmd == NULL) {
			if (decode_header(connection, buffer, &pi))
				goto reconnect;

			cmd = &ack_receiver_tbl[pi.cmd];
			if (pi.cmd >= ARRAY_SIZE(ack_receiver_tbl) || !cmd->fn) {
				drbd_err(connection, "Unexpected meta packet %s (0x%04x)\n",
					 drbd_packet_name(pi.cmd), pi.cmd);
				goto disconnect;
			}
			expect = header_size + cmd->pkt_size;
			if (pi.size != expect - header_size) {
				drbd_err(connection, "Wrong packet size on meta (c: %d, l: %d)\n",
					pi.cmd, pi.size);
				goto reconnect;
			}
			rflags = 0;
		}
		if (received == expect) {
			bool err;

			pi.data = buffer;
			err = cmd->fn(connection, &pi);
			if (err) {
				drbd_err(connection, "%ps failed\n", cmd->fn);
				goto reconnect;
			}

			connection->last_received = jiffies;

			if (cmd == &ack_receiver_tbl[P_PING_ACK]) {
				set_idle_timeout(connection);
				ping_timeout_active = false;
			}

			received = 0;
			expect = header_size;
			cmd = NULL;
			rflags = 0;
		}
	}

	if (0) {
reconnect:
		change_cstate(connection, C_NETWORK_FAILURE, CS_HARD);
	}
	if (0) {
disconnect:
		change_cstate(connection, C_DISCONNECTING, CS_HARD);
	}

	drbd_info(connection, "ack_receiver terminated\n");

	return 0;
}

void drbd_send_acks_wf(struct work_struct *ws)
{
	struct drbd_connection *connection =
		container_of(ws, struct drbd_connection, send_acks_work);
	struct drbd_transport *transport = &connection->transport;
	struct net_conf *nc;
	int tcp_cork, err;

	rcu_read_lock();
	nc = rcu_dereference(transport->net_conf);
	tcp_cork = nc->tcp_cork;
	rcu_read_unlock();

	/* TODO: conditionally cork; it may hurt latency if we cork without
	   much to send */
	if (tcp_cork)
		drbd_cork(connection, CONTROL_STREAM);
	err = drbd_finish_peer_reqs(connection);

	/* but unconditionally uncork unless disabled */
	if (tcp_cork)
		drbd_uncork(connection, CONTROL_STREAM);

	if (err)
		change_cstate(connection, C_NETWORK_FAILURE, CS_HARD);
}

void drbd_send_peer_ack_wf(struct work_struct *ws)
{
	struct drbd_connection *connection =
		container_of(ws, struct drbd_connection, peer_ack_work);

	if (process_peer_ack_list(connection))
		change_cstate(connection, C_NETWORK_FAILURE, CS_HARD);
}

EXPORT_SYMBOL(drbd_alloc_pages); /* for transports */
EXPORT_SYMBOL(drbd_free_pages);
