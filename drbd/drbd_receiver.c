/*
   drbd_receiver.c

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


#include <linux/module.h>

#include <asm/uaccess.h>
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
#define __KERNEL_SYSCALLS__
#include <linux/unistd.h>
#include <linux/vmalloc.h>
#include <linux/random.h>
#include <net/ipv6.h>
#include "drbd_int.h"
#include "drbd_protocol.h"
#include "drbd_req.h"
#include "drbd_vli.h"
#include <linux/scatterlist.h>

#define PRO_FEATURES (FF_TRIM)

struct flush_work {
	struct drbd_work w;
	struct drbd_device *device;
	struct drbd_epoch *epoch;
};

enum finish_epoch {
	FE_STILL_LIVE,
	FE_DESTROYED,
	FE_RECYCLED,
};

int drbd_do_features(struct drbd_connection *connection);
int drbd_do_auth(struct drbd_connection *connection);
static int drbd_disconnected(struct drbd_peer_device *);

static enum finish_epoch drbd_may_finish_epoch(struct drbd_connection *, struct drbd_epoch *, enum epoch_event);
static int e_end_block(struct drbd_work *, int);
static void cleanup_unacked_peer_requests(struct drbd_connection *connection);
static void cleanup_peer_ack_list(struct drbd_connection *connection);
static u64 node_ids_to_bitmap(struct drbd_device *device, u64 node_ids);
static int process_twopc(struct drbd_connection *, struct twopc_reply *, struct packet_info *, unsigned long);

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
		if (--n == 0)
			break; /* found sufficient pages */
		if (tmp == NULL)
			/* insufficient pages, don't use any of them. */
			return NULL;
		page = tmp;
	}

	/* add end of list marker for the returned list */
	set_page_private(page, 0);
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
	set_page_private(chain_last, (unsigned long)*head);
	*head = chain_first;
}

static struct page *__drbd_alloc_pages(unsigned int number, gfp_t gfp_mask)
{
	struct page *page = NULL;
	struct page *tmp = NULL;
	unsigned int i = 0;

	/* Yes, testing drbd_pp_vacant outside the lock is racy.
	 * So what. It saves a spin_lock. */
	if (drbd_pp_vacant >= number) {
		spin_lock(&drbd_pp_lock);
		page = page_chain_del(&drbd_pp_pool, number);
		if (page)
			drbd_pp_vacant -= number;
		spin_unlock(&drbd_pp_lock);
		if (page)
			return page;
	}

	for (i = 0; i < number; i++) {
		tmp = alloc_page(gfp_mask);
		if (!tmp)
			break;
		set_page_private(tmp, (unsigned long)page);
		page = tmp;
	}

	if (i == number)
		return page;

	/* Not enough pages immediately available this time.
	 * No need to jump around here, drbd_alloc_pages will retry this
	 * function "soon". */
	if (page) {
		tmp = page_chain_tail(page, NULL);
		spin_lock(&drbd_pp_lock);
		page_chain_add(&drbd_pp_pool, page, tmp);
		drbd_pp_vacant += i;
		spin_unlock(&drbd_pp_lock);
	}
	return NULL;
}

/* kick lower level device, if we have more than (arbitrary number)
 * reference counts on it, which typically are locally submitted io
 * requests.  don't use unacked_cnt, so we speed up proto A and B, too. */
static void maybe_kick_lo(struct drbd_device *device)
{
	struct disk_conf *dc;
	unsigned int watermark = 1000000;

	rcu_read_lock();
	dc = rcu_dereference(device->ldev->disk_conf);
	if (dc)
		min_not_zero(dc->unplug_watermark, watermark);
	rcu_read_unlock();

	if (atomic_read(&device->local_cnt) >= watermark)
		drbd_kick_lo(device);
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

static void conn_maybe_kick_lo(struct drbd_connection *connection)
{
	struct drbd_resource *resource = connection->resource;
	struct drbd_device *device;
	int vnr;

	idr_for_each_entry(&resource->devices, device, vnr)
		maybe_kick_lo(device);
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
 * Returns a page chain linked via page->private.
 */
struct page *drbd_alloc_pages(struct drbd_transport *transport, unsigned int number,
			      gfp_t gfp_mask)
{
	struct drbd_connection *connection =
		container_of(transport, struct drbd_connection, transport);
	struct page *page = NULL;
	DEFINE_WAIT(wait);
	unsigned int mxb;

	rcu_read_lock();
	mxb = rcu_dereference(transport->net_conf)->max_buffers;
	rcu_read_unlock();

	if (atomic_read(&connection->pp_in_use) < mxb)
		page = __drbd_alloc_pages(number, gfp_mask & ~__GFP_WAIT);

	/* Try to keep the fast path fast, but occasionally we need
	 * to reclaim the pages we lended to the network stack. */
	if (page && atomic_read(&connection->pp_in_use_by_net) > 512)
		drbd_reclaim_net_peer_reqs(connection);

	while (page == NULL) {
		prepare_to_wait(&drbd_pp_wait, &wait, TASK_INTERRUPTIBLE);

		conn_maybe_kick_lo(connection);
		drbd_reclaim_net_peer_reqs(connection);

		if (atomic_read(&connection->pp_in_use) < mxb) {
			page = __drbd_alloc_pages(number, gfp_mask);
			if (page)
				break;
		}

		if (!(gfp_mask & __GFP_WAIT))
			break;

		if (signal_pending(current)) {
			drbd_warn(connection, "drbd_alloc_pages interrupted!\n");
			break;
		}

		if (schedule_timeout(HZ/10) == 0)
			mxb = UINT_MAX;
	}
	finish_wait(&drbd_pp_wait, &wait);

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
	atomic_t *a = is_net ? &connection->pp_in_use_by_net : &connection->pp_in_use;
	int i;

	if (page == NULL)
		return;

	if (drbd_pp_vacant > (DRBD_MAX_BIO_SIZE/PAGE_SIZE) * minor_count)
		i = page_chain_free(page);
	else {
		struct page *tmp;
		tmp = page_chain_tail(page, &i);
		spin_lock(&drbd_pp_lock);
		page_chain_add(&drbd_pp_pool, page, tmp);
		drbd_pp_vacant += i;
		spin_unlock(&drbd_pp_lock);
	}
	i = atomic_sub_return(i, a);
	if (i < 0)
		drbd_warn(connection, "ASSERTION FAILED: %s: %d < 0\n",
			is_net ? "pp_in_use_by_net" : "pp_in_use", i);
	wake_up(&drbd_pp_wait);
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

struct drbd_peer_request *
drbd_alloc_peer_req(struct drbd_peer_device *peer_device, gfp_t gfp_mask) __must_hold(local)
{
	struct drbd_device *device = peer_device->device;
	struct drbd_peer_request *peer_req;

	if (drbd_insert_fault(device, DRBD_FAULT_AL_EE))
		return NULL;

	peer_req = mempool_alloc(drbd_ee_mempool, gfp_mask & ~__GFP_HIGHMEM);
	if (!peer_req) {
		if (!(gfp_mask & __GFP_NOWARN))
			drbd_err(device, "%s: allocation failed\n", __func__);
		return NULL;
	}

	memset(peer_req, 0, sizeof(*peer_req));
	INIT_LIST_HEAD(&peer_req->w.list);
	drbd_clear_interval(&peer_req->i);
	INIT_LIST_HEAD(&peer_req->recv_order);
	peer_req->submit_jif = jiffies;
	peer_req->peer_device = peer_device;
	peer_req->pages = NULL;

	return peer_req;
}

void __drbd_free_peer_req(struct drbd_peer_request *peer_req, int is_net)
{
	struct drbd_peer_device *peer_device = peer_req->peer_device;

	might_sleep();
	if (peer_req->flags & EE_HAS_DIGEST)
		kfree(peer_req->digest);
	drbd_free_pages(&peer_device->connection->transport, peer_req->pages, is_net);
	D_ASSERT(peer_device, atomic_read(&peer_req->pending_bios) == 0);
	D_ASSERT(peer_device, drbd_interval_empty(&peer_req->i));
	mempool_free(peer_req, drbd_ee_mempool);
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
static int drbd_finish_peer_reqs(struct drbd_peer_device *peer_device)
{
	struct drbd_connection *connection = peer_device->connection;
	struct drbd_device *device = peer_device->device;
	LIST_HEAD(work_list);
	LIST_HEAD(reclaimed);
	struct drbd_peer_request *peer_req, *t;
	int err = 0;

	spin_lock_irq(&device->resource->req_lock);
	reclaim_finished_net_peer_reqs(connection, &reclaimed);
	list_splice_init(&device->done_ee, &work_list);
	spin_unlock_irq(&device->resource->req_lock);

	list_for_each_entry_safe(peer_req, t, &reclaimed, w.list)
		drbd_free_net_peer_req(peer_req);

	/* possible callbacks here:
	 * e_end_block, and e_end_resync_block, e_send_discard_write.
	 * all ignore the last argument.
	 */
	list_for_each_entry_safe(peer_req, t, &work_list, w.list) {
		int err2;

		/* list_del not necessary, next/prev members not touched */
		err2 = peer_req->w.cb(&peer_req->w, !!err);
		if (!err)
			err = err2;
		if (!list_empty(&peer_req->recv_order)) {
			drbd_free_pages(&connection->transport, peer_req->pages, 0);
			peer_req->pages = NULL;
		} else
			drbd_free_peer_req(peer_req);
	}
	wake_up(&device->ee_wait);

	return err;
}

static void _drbd_wait_ee_list_empty(struct drbd_device *device,
				     struct list_head *head)
{
	DEFINE_WAIT(wait);

	/* avoids spin_lock/unlock
	 * and calling prepare_to_wait in the fast path */
	while (!list_empty(head)) {
		prepare_to_wait(&device->ee_wait, &wait, TASK_UNINTERRUPTIBLE);
		spin_unlock_irq(&device->resource->req_lock);
		drbd_kick_lo(device);
		schedule();
		finish_wait(&device->ee_wait, &wait);
		spin_lock_irq(&device->resource->req_lock);
	}
}

static void drbd_wait_ee_list_empty(struct drbd_device *device,
				    struct list_head *head)
{
	spin_lock_irq(&device->resource->req_lock);
	_drbd_wait_ee_list_empty(device, head);
	spin_unlock_irq(&device->resource->req_lock);
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

			t = wait_event_timeout(connection->ping_wait, connection->cstate[NOW] < C_CONNECTED, t);

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

static int decode_header(struct drbd_connection *, void *, struct packet_info *);

/* Gets called if a connection is established, or if a new minor gets created
   in a connection */
int drbd_connected(struct drbd_peer_device *peer_device)
{
	struct drbd_device *device = peer_device->device;
	int err;

	atomic_set(&peer_device->packet_seq, 0);
	peer_device->peer_seq = 0;

	err = drbd_send_sync_param(peer_device);
	if (!err)
		err = drbd_send_sizes(peer_device, 0, 0);
	if (!err && device->disk_state[NOW] > D_DISKLESS)
		err = drbd_send_uuids(peer_device, 0, 0);
	if (!err) {
		set_bit(INITIAL_STATE_SENT, &peer_device->flags);
		err = drbd_send_current_state(peer_device);
	}

	clear_bit(USE_DEGR_WFC_T, &peer_device->flags);
	clear_bit(RESIZE_PENDING, &peer_device->flags);
	mod_timer(&device->request_timer, jiffies + HZ); /* just start it here. */
	return err;
}

void connect_timer_fn(unsigned long data)
{
	struct drbd_connection *connection = (struct drbd_connection *) data;
	struct drbd_resource *resource = connection->resource;
	unsigned long irq_flags;

	spin_lock_irqsave(&resource->req_lock, irq_flags);
	drbd_queue_work(&connection->sender_work, &connection->connect_timer_work);
	spin_unlock_irqrestore(&resource->req_lock, irq_flags);
}

void conn_connect2(struct drbd_connection *connection)
{
	struct drbd_peer_device *peer_device;
	int vnr;

	atomic_set(&connection->ap_in_flight, 0);

	rcu_read_lock();
	idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
		struct drbd_device *device = peer_device->device;
		kref_get(&device->kref);
		/* connection cannot go away: caller holds a reference. */
		rcu_read_unlock();
		drbd_connected(peer_device);
		rcu_read_lock();
		kref_put(&device->kref, drbd_destroy_device);
	}
	rcu_read_unlock();
}

void conn_disconnect(struct drbd_connection *connection);

int connect_work(struct drbd_work *work, int cancel)
{
	struct drbd_connection *connection =
		container_of(work, struct drbd_connection, connect_timer_work);
	enum drbd_state_rv rv;

	rv = change_cstate(connection, C_CONNECTED, CS_SERIALIZE | CS_VERBOSE | CS_DONT_RETRY);

	if (rv >= SS_SUCCESS) {
		conn_connect2(connection);
	} else if (rv == SS_TIMEOUT || rv == SS_CONCURRENT_ST_CHG) {
		connection->connect_timer.expires = jiffies + HZ/20;
		add_timer(&connection->connect_timer);
		return 0; /* Return early. Keep the reference on the connection! */
	} else {
		drbd_info(connection, "Failure to connect; retrying\n");
		change_cstate(connection, C_NETWORK_FAILURE, CS_HARD);
	}

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
	bool discard_my_data;
	struct net_conf *nc;

start:
	clear_bit(DISCONNECT_EXPECTED, &connection->flags);
	if (change_cstate(connection, C_CONNECTING, CS_VERBOSE) < SS_SUCCESS) {
		/* We do not have a network config. */
		return false;
	}

	/* Assume that the peer only understands protocol 80 until we know better.  */
	connection->agreed_pro_version = 80;

	err = transport->ops->connect(transport);
	if (err == -EAGAIN)
		goto retry;
	else if (err < 0) {
		drbd_warn(connection, "Failed to initiate connection, err=%d\n", err);
		goto abort;
	}

	connection->last_received = jiffies;

	rcu_read_lock();
	nc = rcu_dereference(connection->transport.net_conf);
	ping_timeo = nc->ping_timeo;
	ping_int = nc->ping_int;
	rcu_read_unlock();

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

	transport->ops->set_rcvtimeo(transport, DATA_STREAM, MAX_SCHEDULE_TIMEOUT);

	discard_my_data = test_bit(CONN_DISCARD_MY_DATA, &connection->flags);

	if (drbd_send_protocol(connection) == -EOPNOTSUPP)
		goto abort;

	rcu_read_lock();
	idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
		clear_bit(INITIAL_STATE_SENT, &peer_device->flags);
		clear_bit(INITIAL_STATE_RECEIVED, &peer_device->flags);
	}
	idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
		struct drbd_device *device = peer_device->device;

		if (discard_my_data)
			set_bit(DISCARD_MY_DATA, &device->flags);
		else
			clear_bit(DISCARD_MY_DATA, &device->flags);
	}
	rcu_read_unlock();

	drbd_thread_start(&connection->ack_receiver);
	connection->ack_sender =
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,3,0)
		alloc_ordered_workqueue("drbd_as_%s", WQ_MEM_RECLAIM, connection->resource->name);
#else
		create_singlethread_workqueue("drbd_ack_sender");
#endif
	if (!connection->ack_sender) {
		drbd_err(connection, "Failed to create workqueue ack_sender\n");
		goto abort;
	}

	if (connection->agreed_pro_version >= 110) {
		if (resource->res_opts.node_id < connection->peer_node_id) {
			kref_get(&connection->kref);
			kref_debug_get(&connection->kref_debug, 11);
			connection->connect_timer_work.cb = connect_work;
			timeout = twopc_retry_timeout(resource, 0);
			drbd_debug(connection, "Waiting for %ums to avoid transaction "
				   "conflicts\n", jiffies_to_msecs(timeout));
			connection->connect_timer.expires = jiffies + timeout;
			add_timer(&connection->connect_timer);
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
	conn_disconnect(connection);
	schedule_timeout_interruptible(HZ);
	goto start;

abort:
	change_cstate(connection, C_DISCONNECTING, CS_HARD);
	return false;
}

int decode_header(struct drbd_connection *connection, void *header, struct packet_info *pi)
{
	unsigned int header_size = drbd_header_size(connection);

	if (header_size == sizeof(struct p_header100) &&
	    *(__be32 *)header == cpu_to_be32(DRBD_MAGIC_100)) {
		struct p_header100 *h = header;
		if (h->pad != 0) {
			drbd_err(connection, "Header padding is not zero\n");
			return -EINVAL;
		}
		pi->vnr = (s16)be16_to_cpu(h->volume);
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

static enum finish_epoch drbd_flush_after_epoch(struct drbd_connection *connection, struct drbd_epoch *epoch)
{
	int rv;
	struct drbd_resource *resource = connection->resource;
	struct drbd_device *device;
	int vnr;

	if (resource->write_ordering >= WO_BDEV_FLUSH) {
		rcu_read_lock();
		idr_for_each_entry(&resource->devices, device, vnr) {
			if (!get_ldev(device))
				continue;
			kref_get(&device->kref);
			rcu_read_unlock();

			/* Right now, we have only this one synchronous code path
			 * for flushes between request epochs.
			 * We may want to make those asynchronous,
			 * or at least parallelize the flushes to the volume devices.
			 */
			device->flush_jif = jiffies;
			set_bit(FLUSH_PENDING, &device->flags);
			rv = blkdev_issue_flush(device->ldev->backing_bdev, GFP_NOIO, NULL);
			clear_bit(FLUSH_PENDING, &device->flags);
			if (rv) {
				drbd_info(device, "local disk flush failed with status %d\n", rv);
				/* would rather check on EOPNOTSUPP, but that is not reliable.
				 * don't try again for ANY return value != 0
				 * if (rv == -EOPNOTSUPP) */
				drbd_bump_write_ordering(resource, NULL, WO_DRAIN_IO);
			}
			put_ldev(device);
			kref_put(&device->kref, drbd_destroy_device);

			rcu_read_lock();
			if (rv)
				break;
		}
		rcu_read_unlock();
	}

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
				spin_unlock(&connection->epoch_lock);
				drbd_send_b_ack(epoch->connection, epoch->barrier_nr, epoch_size);
				spin_lock(&connection->epoch_lock);
			}
#if 0
			/* FIXME: dec unacked on connection, once we have
			 * something to count pending connection packets in. */
			if (test_bit(DE_HAVE_BARRIER_NUMBER, &epoch->flags))
				dec_unacked(epoch->connection);
#endif

			if (connection->current_epoch != epoch) {
				next_epoch = list_entry(epoch->list.next, struct drbd_epoch, list);
				list_del(&epoch->list);
				ev = EV_BECAME_LAST | (ev & EV_CLEANUP);
				connection->epochs--;
				kfree(epoch);

				if (rv == FE_STILL_LIVE)
					rv = FE_DESTROYED;
			} else {
				epoch->flags = 0;
				atomic_set(&epoch->epoch_size, 0);
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
			fw->device = NULL; /* FIXME drop this member, it is unused. */
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

void conn_wait_active_ee_empty(struct drbd_connection *connection);

/**
 * drbd_submit_peer_request()
 * @device:	DRBD device.
 * @peer_req:	peer request
 * @rw:		flag field, see bio->bi_rw
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
int drbd_submit_peer_request(struct drbd_device *device,
			     struct drbd_peer_request *peer_req,
			     const unsigned rw, const int fault_type)
{
	struct bio *bios = NULL;
	struct bio *bio;
	struct page *page = peer_req->pages;
	sector_t sector = peer_req->i.sector;
	unsigned data_size = peer_req->i.size;
	unsigned n_bios = 0;
	unsigned nr_pages = DIV_ROUND_UP(data_size, PAGE_SIZE);
	int err = -ENOMEM;

	if (peer_req->flags & EE_IS_TRIM_USE_ZEROOUT) {
		/* wait for all pending IO completions, before we start
		 * zeroing things out. */
		conn_wait_active_ee_empty(peer_req->peer_device->connection);
		/* add it to the active list now,
		 * so we can find it to present it in debugfs */
		peer_req->submit_jif = jiffies;
		peer_req->flags |= EE_SUBMITTED;
		spin_lock_irq(&device->resource->req_lock);
		list_add_tail(&peer_req->w.list, &device->active_ee);
		spin_unlock_irq(&device->resource->req_lock);
		if (blkdev_issue_zeroout(device->ldev->backing_bdev,
			sector, data_size >> 9, GFP_NOIO, false))
			peer_req->flags |= EE_WAS_ERROR;
		drbd_endio_write_sec_final(peer_req);
		return 0;
	}

	/* Discards don't have any payload.
	 * But the scsi layer still expects a bio_vec it can use internally,
	 * see sd_setup_discard_cmnd() and blk_add_request_payload(). */
	if (peer_req->flags & EE_IS_TRIM)
		nr_pages = 1;

	/* In most cases, we will only need one bio.  But in case the lower
	 * level restrictions happen to be different at this offset on this
	 * side than those of the sending peer, we may need to submit the
	 * request in more than one bio.
	 *
	 * Plain bio_alloc is good enough here, this is no DRBD internally
	 * generated bio, but a bio allocated on behalf of the peer.
	 */
next_bio:
	bio = bio_alloc(GFP_NOIO, nr_pages);
	if (!bio) {
		drbd_err(device, "submit_ee: Allocation of a bio failed (nr_pages=%u)\n", nr_pages);
		goto fail;
	}
	/* > peer_req->i.sector, unless this is the first bio */
	DRBD_BIO_BI_SECTOR(bio) = sector;
	bio->bi_bdev = device->ldev->backing_bdev;
	/* we special case some flags in the multi-bio case, see below
	 * (REQ_UNPLUG, REQ_FLUSH, or BIO_RW_BARRIER in older kernels) */
	bio->bi_rw = rw;
	bio->bi_private = peer_req;
	bio->bi_end_io = drbd_peer_request_endio;

	bio->bi_next = bios;
	bios = bio;
	++n_bios;

	if (rw & DRBD_REQ_DISCARD) {
		DRBD_BIO_BI_SIZE(bio) = data_size;
		goto submit;
	}

	page_chain_for_each(page) {
		unsigned len = min_t(unsigned, data_size, PAGE_SIZE);
		if (!bio_add_page(bio, page, len, 0)) {
			/* A single page must always be possible!
			 * But in case it fails anyways,
			 * we deal with it, and complain (below). */
			if (bio->bi_vcnt == 0) {
				drbd_err(device,
					"bio_add_page failed for len=%u, "
					"bi_vcnt=0 (bi_sector=%llu)\n",
					len, (uint64_t)DRBD_BIO_BI_SECTOR(bio));
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
submit:
	D_ASSERT(device, page == NULL);

	atomic_set(&peer_req->pending_bios, n_bios);
	/* for debugfs: update timestamp, mark as submitted */
	peer_req->submit_jif = jiffies;
	peer_req->flags |= EE_SUBMITTED;
	do {
		bio = bios;
		bios = bios->bi_next;
		bio->bi_next = NULL;

		/* strip off REQ_UNPLUG unless it is the last bio */
		if (bios)
			bio->bi_rw &= ~DRBD_REQ_UNPLUG;
		drbd_generic_make_request(device, fault_type, bio);

		/* strip off REQ_FLUSH,
		 * unless it is the first or last bio */
		if (bios && bios->bi_next)
			bios->bi_rw &= ~DRBD_REQ_FLUSH;
	} while (bios);
	maybe_kick_lo(device);
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

	/* Wake up any processes waiting for this peer request to complete.  */
	if (i->waiting)
		wake_up(&device->misc_wait);
}

/**
 * w_e_reissue() - Worker callback; Resubmit a bio, without REQ_HARDBARRIER set
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
	err = drbd_submit_peer_request(device, peer_req, WRITE, DRBD_FAULT_DT_WR);
	switch (err) {
	case -ENOMEM:
		peer_req->w.cb = w_e_reissue;
		drbd_queue_work(&peer_device->connection->sender_work,
				&peer_req->w);
		/* retry later; fall through */
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
		drbd_may_finish_epoch(peer_device->connection, peer_req->epoch, EV_PUT + EV_CLEANUP);
		drbd_free_peer_req(peer_req);
		drbd_err(device, "submit failed, triggering re-connect\n");
		return err;
	}
}

void conn_wait_active_ee_empty(struct drbd_connection *connection)
{
	struct drbd_peer_device *peer_device;
	int vnr;

	rcu_read_lock();
	idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
		struct drbd_device *device = peer_device->device;

		kref_get(&device->kref);
		rcu_read_unlock();
		drbd_wait_ee_list_empty(device, &device->active_ee);
		kref_put(&device->kref, drbd_destroy_device);
		rcu_read_lock();
	}
	rcu_read_unlock();
}

static void conn_wait_done_ee_empty(struct drbd_connection *connection)
{
	struct drbd_peer_device *peer_device;
	int vnr;

	rcu_read_lock();
	idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
		struct drbd_device *device = peer_device->device;

		kref_get(&device->kref);
		rcu_read_unlock();
		drbd_wait_ee_list_empty(device, &device->done_ee);
		kref_put(&device->kref, drbd_destroy_device);
		rcu_read_lock();
	}
	rcu_read_unlock();
}

#ifdef blk_queue_plugged
void drbd_unplug_all_devices(struct drbd_resource *resource)
{
	struct drbd_device *device;
	int vnr;

	rcu_read_lock();
	idr_for_each_entry(&resource->devices, device, vnr) {
		kref_get(&device->kref);
		rcu_read_unlock();
		drbd_kick_lo(device);
		kref_put(&device->kref, drbd_destroy_device);
		rcu_read_lock();
	}
	rcu_read_unlock();
}
#else
void drbd_unplug_all_devices(struct drbd_resource *resource)
{
}
#endif

static int receive_Barrier(struct drbd_connection *connection, struct packet_info *pi)
{
	int rv, issue_flush;
	struct p_barrier *p = pi->data;
	struct drbd_epoch *epoch;

	drbd_unplug_all_devices(connection->resource);

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
			conn_wait_active_ee_empty(connection);
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
	epoch = kmalloc(sizeof(struct drbd_epoch), GFP_NOIO);
	if (!epoch) {
		drbd_warn(connection, "Allocation of an epoch failed, slowing down\n");
		issue_flush = !test_and_set_bit(DE_BARRIER_IN_NEXT_EPOCH_ISSUED, &connection->current_epoch->flags);
		conn_wait_active_ee_empty(connection);
		if (issue_flush) {
			rv = drbd_flush_after_epoch(connection, connection->current_epoch);
			if (rv == FE_RECYCLED)
				return 0;
		}

		conn_wait_done_ee_empty(connection);

		return 0;
	}

	epoch->flags = 0;
	atomic_set(&epoch->epoch_size, 0);
	atomic_set(&epoch->active, 0);

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

/* used from receive_RSDataReply (recv_resync_read)
 * and from receive_Data */
static struct drbd_peer_request *
read_in_block(struct drbd_peer_device *peer_device, u64 id, sector_t sector,
	      struct packet_info *pi) __must_hold(local)
{
	struct drbd_device *device = peer_device->device;
	const sector_t capacity = drbd_get_capacity(device->this_bdev);
	struct drbd_peer_request *peer_req;
	int digest_size, err;
	unsigned int data_size = pi->size;
	void *dig_in = peer_device->connection->int_dig_in;
	void *dig_vv = peer_device->connection->int_dig_vv;
	struct p_trim *trim = (pi->cmd == P_TRIM) ? pi->data : NULL;
	struct drbd_transport *transport = &peer_device->connection->transport;
	struct drbd_transport_ops *tr_ops = transport->ops;

	digest_size = 0;
	if (!trim && peer_device->connection->peer_integrity_tfm) {
		digest_size = crypto_hash_digestsize(peer_device->connection->peer_integrity_tfm);
		/*
		 * FIXME: Receive the incoming digest into the receive buffer
		 *	  here, together with its struct p_data?
		 */
		err = drbd_recv_into(peer_device->connection, dig_in, digest_size);
		if (err)
			return NULL;
		data_size -= digest_size;
	}

	if (trim) {
		D_ASSERT(peer_device, data_size == 0);
		data_size = be32_to_cpu(trim->size);
	}

	if (!expect(peer_device, IS_ALIGNED(data_size, 512)))
		return NULL;
	/* prepare for larger trim requests. */
	if (!trim && !expect(peer_device, data_size <= DRBD_MAX_BIO_SIZE))
		return NULL;

	/* even though we trust out peer,
	 * we sometimes have to double check. */
	if (sector + (data_size>>9) > capacity) {
		drbd_err(device, "request from peer beyond end of local disk: "
			"capacity: %llus < sector: %llus + size: %u\n",
			(unsigned long long)capacity,
			(unsigned long long)sector, data_size);
		return NULL;
	}

	peer_req = drbd_alloc_peer_req(peer_device, GFP_TRY);
	if (!peer_req)
		return NULL;
	peer_req->i.size = data_size;
	peer_req->i.sector = sector;
	peer_req->block_id = id;

	peer_req->flags |= EE_WRITE;
	if (trim)
		return peer_req;

	err = tr_ops->recv_pages(transport, &peer_req->pages, data_size);
	if (err)
		goto fail;

	if (drbd_insert_fault(device, DRBD_FAULT_RECEIVE)) {
		unsigned long *data;
		drbd_err(device, "Fault injection: Corrupting data on receive\n");
		data = kmap(peer_req->pages);
		data[0] = ~data[0];
		kunmap(peer_req->pages);
	}

	if (digest_size) {
		drbd_csum_ee(peer_device->connection->peer_integrity_tfm, peer_req, dig_vv);
		if (memcmp(dig_in, dig_vv, digest_size)) {
			drbd_err(device, "Digest integrity check FAILED: %llus +%u\n",
				(unsigned long long)sector, data_size);
			goto fail;
		}
	}
	peer_device->recv_cnt += data_size >> 9;
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
	DRBD_BIO_VEC_TYPE bvec;
	DRBD_ITER_TYPE iter;
	struct bio *bio;
	int digest_size, err, expect;
	void *dig_in = peer_device->connection->int_dig_in;
	void *dig_vv = peer_device->connection->int_dig_vv;

	digest_size = 0;
	if (peer_device->connection->peer_integrity_tfm) {
		digest_size = crypto_hash_digestsize(peer_device->connection->peer_integrity_tfm);
		err = drbd_recv_into(peer_device->connection, dig_in, digest_size);
		if (err)
			return err;
		data_size -= digest_size;
	}

	/* optimistically update recv_cnt.  if receiving fails below,
	 * we disconnect anyways, and counters will be reset. */
	peer_device->recv_cnt += data_size >> 9;

	bio = req->master_bio;
	D_ASSERT(peer_device->device, sector == DRBD_BIO_BI_SECTOR(bio));

	bio_for_each_segment(bvec, bio, iter) {
		void *mapped = kmap(bvec BVD bv_page) + bvec BVD bv_offset;
		expect = min_t(int, data_size, bvec BVD bv_len);
		err = drbd_recv_into(peer_device->connection, mapped, expect);
		kunmap(bvec BVD bv_page);
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

static int recv_resync_read(struct drbd_peer_device *peer_device, sector_t sector,
			    struct packet_info *pi) __releases(local)
{
	struct drbd_device *device = peer_device->device;
	struct drbd_peer_request *peer_req;

	peer_req = read_in_block(peer_device, ID_SYNCER, sector, pi);
	if (!peer_req)
		return -EIO;

	if (test_bit(UNSTABLE_RESYNC, &peer_device->flags))
		clear_bit(STABLE_RESYNC, &device->flags);

	dec_rs_pending(peer_device);

	inc_unacked(peer_device);
	/* corresponding dec_unacked() in e_end_resync_block()
	 * respective _drbd_clear_done_ee */

	peer_req->w.cb = e_end_resync_block;
	peer_req->submit_jif = jiffies;

	spin_lock_irq(&device->resource->req_lock);
	list_add_tail(&peer_req->w.list, &device->sync_ee);
	spin_unlock_irq(&device->resource->req_lock);

	atomic_add(pi->size >> 9, &device->rs_sect_ev);

	/* Seting all peer out of sync here. Sync source peer will be set
	   in sync when the write completes. Other peers will be set in
	   sync by the sync source with a P_PEERS_IN_SYNC packet soon. */
	drbd_set_all_out_of_sync(device, peer_req->i.sector, peer_req->i.size);

	if (drbd_submit_peer_request(device, peer_req, WRITE, DRBD_FAULT_RS_WR) == 0)
		return 0;

	/* don't care for the reason here */
	drbd_err(device, "submit failed, triggering re-connect\n");
	spin_lock_irq(&device->resource->req_lock);
	list_del(&peer_req->w.list);
	spin_unlock_irq(&device->resource->req_lock);

	drbd_free_peer_req(peer_req);
	return -EIO;
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

	/* drbd_remove_request_interval() is done in _req_may_be_done, to avoid
	 * special casing it there for the various failure cases.
	 * still no race with drbd_fail_pending_reads */
	err = recv_dless_read(peer_device, req, sector, pi->size);
	if (!err)
		req_mod(req, DATA_RECEIVED, peer_device);
	/* else: nothing. handled from drbd_disconnect...
	 * I don't think we may complete this just yet
	 * in case we are "on-disconnect: freeze" */

	return err;
}

static int receive_RSDataReply(struct drbd_connection *connection, struct packet_info *pi)
{
	struct drbd_peer_device *peer_device;
	struct drbd_device *device;
	sector_t sector;
	int err;
	struct p_data *p = pi->data;

	peer_device = conn_peer_device(connection, pi->vnr);
	if (!peer_device)
		return -EIO;
	device = peer_device->device;

	sector = be64_to_cpu(p->sector);
	D_ASSERT(device, p->block_id == ID_SYNCER);

	if (get_ldev(device)) {
		err = recv_resync_read(peer_device, sector, pi);
		if (err)
			put_ldev(device);
	} else {
		if (drbd_ratelimit())
			drbd_err(device, "Can not write resync data to local disk.\n");

		err = ignore_remaining_packet(connection, pi->size);

		drbd_send_ack_dp(peer_device, P_NEG_ACK, p, pi->size);
	}

	atomic_add(pi->size >> 9, &peer_device->rs_sect_in);

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
		if ((req->rq_state[0] & RQ_LOCAL_PENDING) ||
		   !(req->rq_state[0] & RQ_POSTPONED))
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
		if (likely((peer_req->flags & EE_WAS_ERROR) == 0)) {
			pcmd = (peer_device->repl_state[NOW] >= L_SYNC_SOURCE &&
				peer_device->repl_state[NOW] <= L_PAUSED_SYNC_T &&
				peer_req->flags & EE_MAY_SET_IN_SYNC) ?
				P_RS_WRITE_ACK : P_WRITE_ACK;
			err = drbd_send_ack(peer_device, pcmd, peer_req);
			if (pcmd == P_RS_WRITE_ACK)
				drbd_set_in_sync(peer_device, sector, peer_req->i.size);
		} else {
			err = drbd_send_ack(peer_device, P_NEG_ACK, peer_req);
			/* we expect it to be marked out of sync anyways...
			 * maybe assert this?  */
		}
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
static bool overlapping_resync_write(struct drbd_device *device, struct drbd_peer_request *peer_req)
{
	struct drbd_peer_request *rs_req;
	bool rv = 0;

	spin_lock_irq(&device->resource->req_lock);
	list_for_each_entry(rs_req, &device->sync_ee, w.list) {
		if (overlaps(peer_req->i.sector, peer_req->i.size,
			     rs_req->i.sector, rs_req->i.size)) {
			rv = 1;
			break;
		}
	}
	spin_unlock_irq(&device->resource->req_lock);

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

/* see also bio_flags_to_wire()
 * DRBD_REQ_*, because we need to semantically map the flags to data packet
 * flags and back. We may replicate to other kernel versions. */
static unsigned long wire_flags_to_bio(struct drbd_connection *connection, u32 dpf)
{
	if (connection->agreed_pro_version >= 95)
		return  (dpf & DP_RW_SYNC ? DRBD_REQ_SYNC : 0) |
			(dpf & DP_UNPLUG ? DRBD_REQ_UNPLUG : 0) |
			(dpf & DP_FUA ? DRBD_REQ_FUA : 0) |
			(dpf & DP_FLUSH ? DRBD_REQ_FLUSH : 0) |
			(dpf & DP_DISCARD ? DRBD_REQ_DISCARD : 0);

	/* else: we used to communicate one bit only in older DRBD */
	return dpf & DP_RW_SYNC ? (DRBD_REQ_SYNC | DRBD_REQ_UNPLUG) : 0;
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
		if (!(req->rq_state[0] & RQ_POSTPONED))
			continue;
		req->rq_state[0] &= ~RQ_POSTPONED;
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
			list_add_tail(&peer_req->w.list, &device->done_ee);
			queue_work(connection->ack_sender, &peer_req->peer_device->send_acks_work);

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

			if (req->rq_state[0] & RQ_LOCAL_PENDING ||
			    !(req->rq_state[0] & RQ_POSTPONED)) {
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

/* mirrored write */
static int receive_Data(struct drbd_connection *connection, struct packet_info *pi)
{
	struct drbd_peer_device *peer_device;
	struct drbd_device *device;
	struct net_conf *nc;
	sector_t sector;
	struct drbd_peer_request *peer_req;
	struct p_data *p = pi->data;
	u32 peer_seq = be32_to_cpu(p->seq_num);
	int rw = WRITE;
	u32 dp_flags;
	int err, tp;

	peer_device = conn_peer_device(connection, pi->vnr);
	if (!peer_device)
		return -EIO;
	device = peer_device->device;

	if (!get_ldev(device)) {
		int err2;

		err = wait_for_and_update_peer_seq(peer_device, peer_seq);
		drbd_send_ack_dp(peer_device, P_NEG_ACK, p, pi->size);
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

	sector = be64_to_cpu(p->sector);
	peer_req = read_in_block(peer_device, p->block_id, sector, pi);
	if (!peer_req) {
		put_ldev(device);
		return -EIO;
	}

	peer_req->dagtag_sector = connection->last_dagtag_sector + (peer_req->i.size >> 9);
	connection->last_dagtag_sector = peer_req->dagtag_sector;

	peer_req->w.cb = e_end_block;
	peer_req->submit_jif = jiffies;
	peer_req->flags |= EE_APPLICATION;

	dp_flags = be32_to_cpu(p->dp_flags);
	rw |= wire_flags_to_bio(connection, dp_flags);
	if (pi->cmd == P_TRIM) {
		struct request_queue *q = bdev_get_queue(device->ldev->backing_bdev);
		peer_req->flags |= EE_IS_TRIM;
		if (!blk_queue_discard(q))
			peer_req->flags |= EE_IS_TRIM_USE_ZEROOUT;
		D_ASSERT(peer_device, peer_req->i.size > 0);
		D_ASSERT(peer_device, rw & DRBD_REQ_DISCARD);
		D_ASSERT(peer_device, peer_req->pages == NULL);
	} else if (peer_req->pages == NULL) {
		D_ASSERT(device, peer_req->i.size == 0);
		D_ASSERT(device, dp_flags & DP_FLUSH);
	}

	if (dp_flags & DP_MAY_SET_IN_SYNC)
		peer_req->flags |= EE_MAY_SET_IN_SYNC;

	/* last "fixes" to rw flags.
	 * Strip off BIO_RW_BARRIER unconditionally,
	 * it is not supposed to be here anyways.
	 * (Was FUA or FLUSH on the peer,
	 * and got translated to BARRIER on this side).
	 * Note that the epoch handling code below
	 * may add it again, though.
	 */
	rw &= ~DRBD_REQ_HARDBARRIER;

	spin_lock(&connection->epoch_lock);
	peer_req->epoch = connection->current_epoch;
	atomic_inc(&peer_req->epoch->epoch_size);
	atomic_inc(&peer_req->epoch->active);

	if (connection->resource->write_ordering == WO_BIO_BARRIER &&
	    atomic_read(&peer_req->epoch->epoch_size) == 1) {
		struct drbd_epoch *epoch;
		/* Issue a barrier if we start a new epoch, and the previous epoch
		   was not a epoch containing a single request which already was
		   a Barrier. */
		epoch = list_entry(peer_req->epoch->list.prev, struct drbd_epoch, list);
		if (epoch == peer_req->epoch) {
			set_bit(DE_CONTAINS_A_BARRIER, &peer_req->epoch->flags);
			rw |= DRBD_REQ_FLUSH | DRBD_REQ_FUA;
			peer_req->flags |= EE_IS_BARRIER;
		} else {
			if (atomic_read(&epoch->epoch_size) > 1 ||
			    !test_bit(DE_CONTAINS_A_BARRIER, &epoch->flags)) {
				set_bit(DE_BARRIER_IN_NEXT_EPOCH_ISSUED, &epoch->flags);
				set_bit(DE_CONTAINS_A_BARRIER, &peer_req->epoch->flags);
				rw |= DRBD_REQ_FLUSH | DRBD_REQ_FUA;
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
			dp_flags |= DP_SEND_WRITE_ACK;
			break;
		case DRBD_PROT_B:
			dp_flags |= DP_SEND_RECEIVE_ACK;
			break;
		}
	}
	rcu_read_unlock();

	if (dp_flags & DP_SEND_WRITE_ACK) {
		peer_req->flags |= EE_SEND_WRITE_ACK;
		inc_unacked(peer_device);
		/* corresponding dec_unacked() in e_end_block()
		 * respective _drbd_clear_done_ee */
	}

	if (dp_flags & DP_SEND_RECEIVE_ACK) {
		/* I really don't like it that the receiver thread
		 * sends on the msock, but anyways */
		drbd_send_ack(peer_device, P_RECV_ACK, peer_req);
	}

	if (tp) {
		/* two primaries implies protocol C */
		D_ASSERT(device, dp_flags & DP_SEND_WRITE_ACK);
		peer_req->flags |= EE_IN_INTERVAL_TREE;
		err = wait_for_and_update_peer_seq(peer_device, peer_seq);
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
		update_peer_seq(peer_device, peer_seq);
		spin_lock_irq(&device->resource->req_lock);
	}
	/* if we use the zeroout fallback code, we process synchronously
	 * and we wait for all pending requests, respectively wait for
	 * active_ee to become empty in drbd_submit_peer_request();
	 * better not add ourselves here. */
	if ((peer_req->flags & EE_IS_TRIM_USE_ZEROOUT) == 0)
		list_add_tail(&peer_req->w.list, &device->active_ee);
	if (connection->agreed_pro_version >= 110)
		list_add_tail(&peer_req->recv_order, &connection->peer_requests);
	spin_unlock_irq(&device->resource->req_lock);

	if (peer_device->repl_state[NOW] == L_SYNC_TARGET)
		wait_event(device->ee_wait, !overlapping_resync_write(device, peer_req));

	drbd_al_begin_io_for_peer(peer_device, &peer_req->i);

	err = drbd_submit_peer_request(device, peer_req, rw, DRBD_FAULT_DT_WR);
	if (!err)
		return 0;

	/* don't care for the reason here */
	drbd_err(device, "submit failed, triggering re-connect\n");
	spin_lock_irq(&device->resource->req_lock);
	list_del(&peer_req->w.list);
	list_del_init(&peer_req->recv_order);
	drbd_remove_peer_req_interval(device, peer_req);
	spin_unlock_irq(&device->resource->req_lock);
	drbd_al_complete_io(device, &peer_req->i);

out_interrupted:
	drbd_may_finish_epoch(connection, peer_req->epoch, EV_PUT + EV_CLEANUP);
	put_ldev(device);
	drbd_free_peer_req(peer_req);
	return err;
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
	unsigned long db, dt, dbdt;
	unsigned int c_min_rate;
	int curr_events;

	rcu_read_lock();
	c_min_rate = rcu_dereference(peer_device->conf)->c_min_rate;
	rcu_read_unlock();

	/* feature disabled? */
	if (c_min_rate == 0)
		return false;

	curr_events = drbd_backing_bdev_events(device->ldev->backing_bdev->bd_contains->bd_disk)
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

static int receive_DataRequest(struct drbd_connection *connection, struct packet_info *pi)
{
	struct drbd_peer_device *peer_device;
	struct drbd_device *device;
	sector_t sector;
	sector_t capacity;
	struct drbd_peer_request *peer_req;
	struct digest_info *di = NULL;
	int size, verb;
	unsigned int fault_type;
	struct p_block_req *p =	pi->data;
	enum drbd_disk_state min_d_state;
	int err;

	peer_device = conn_peer_device(connection, pi->vnr);
	if (!peer_device)
		return -EIO;
	device = peer_device->device;
	capacity = drbd_get_capacity(device->this_bdev);

	sector = be64_to_cpu(p->sector);
	size   = be32_to_cpu(p->blksize);

	if (size <= 0 || !IS_ALIGNED(size, 512) || size > DRBD_MAX_BIO_SIZE) {
		drbd_err(device, "%s:%d: sector: %llus, size: %u\n", __FILE__, __LINE__,
				(unsigned long long)sector, size);
		return -EINVAL;
	}
	if (sector + (size>>9) > capacity) {
		drbd_err(device, "%s:%d: sector: %llus, size: %u\n", __FILE__, __LINE__,
				(unsigned long long)sector, size);
		return -EINVAL;
	}

	min_d_state = pi->cmd == P_DATA_REQUEST ? D_UP_TO_DATE : D_OUTDATED;
	if (!get_ldev_if_state(device, min_d_state)) {
		verb = 1;
		switch (pi->cmd) {
		case P_DATA_REQUEST:
			drbd_send_ack_rp(peer_device, P_NEG_DREPLY, p);
			break;
		case P_RS_DATA_REQUEST:
		case P_CSUM_RS_REQUEST:
		case P_OV_REQUEST:
			drbd_send_ack_rp(peer_device, P_NEG_RS_DREPLY , p);
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
			drbd_err(device, "Can not satisfy peer's read request, "
			    "no local data.\n");

		/* drain possibly payload */
		return ignore_remaining_packet(connection, pi->size);
	}

	peer_req = drbd_alloc_peer_req(peer_device, GFP_TRY);
	err = -ENOMEM;
	if (!peer_req)
		goto fail;
	if (size) {
		peer_req->pages = drbd_alloc_pages(&peer_device->connection->transport,
			DIV_ROUND_UP(size, PAGE_SIZE), GFP_TRY);
		if (!peer_req->pages)
			goto fail2;
	}
	peer_req->i.size = size;
	peer_req->i.sector = sector;
	peer_req->block_id = p->block_id;

	switch (pi->cmd) {
	case P_DATA_REQUEST:
		peer_req->w.cb = w_e_end_data_req;
		fault_type = DRBD_FAULT_DT_RD;
		/* application IO, don't drbd_rs_begin_io */
		peer_req->flags |= EE_APPLICATION;
		goto submit;

	case P_RS_DATA_REQUEST:
		peer_req->w.cb = w_e_end_rsdata_req;
		fault_type = DRBD_FAULT_RS_RD;
		break;

	case P_OV_REPLY:
	case P_CSUM_RS_REQUEST:
		fault_type = DRBD_FAULT_RS_RD;
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
			atomic_add(size >> 9, &peer_device->rs_sect_in);
			peer_req->w.cb = w_e_end_ov_reply;
			dec_rs_pending(peer_device);
			/* drbd_rs_begin_io done when we sent this request,
			 * but accounting still needs to be done. */
			goto submit_for_resync;
		}
		break;

	case P_OV_REQUEST:
		if (peer_device->ov_start_sector == ~(sector_t)0 &&
		    connection->agreed_pro_version >= 90) {
			unsigned long now = jiffies;
			int i;
			peer_device->ov_start_sector = sector;
			peer_device->ov_position = sector;
			peer_device->ov_left = drbd_bm_bits(device) - BM_SECT_TO_BIT(sector);
			peer_device->rs_total = peer_device->ov_left;
			for (i = 0; i < DRBD_SYNC_MARKS; i++) {
				peer_device->rs_mark_left[i] = peer_device->ov_left;
				peer_device->rs_mark_time[i] = now;
			}
			drbd_info(device, "Online Verify start sector: %llu\n",
					(unsigned long long)sector);
		}
		peer_req->w.cb = w_e_end_ov_req;
		fault_type = DRBD_FAULT_RS_RD;
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
	list_add_tail(&peer_req->w.list, &device->read_ee);
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
	if (drbd_submit_peer_request(device, peer_req, READ, fault_type) == 0)
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
static int drbd_asb_recover_0p(struct drbd_peer_device *peer_device) __must_hold(local)
{
	const int node_id = peer_device->device->resource->res_opts.node_id;
	int self, peer, rv = -100;
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
		drbd_err(peer_device, "Configuration error.\n");
		break;
	case ASB_DISCONNECT:
		break;
	case ASB_DISCARD_YOUNGER_PRI:
		if (self == 0 && peer == 1) {
			rv = -2;
			break;
		}
		if (self == 1 && peer == 0) {
			rv =  2;
			break;
		}
		/* Else fall through to one of the other strategies... */
	case ASB_DISCARD_OLDER_PRI:
		if (self == 0 && peer == 1) {
			rv = 2;
			break;
		}
		if (self == 1 && peer == 0) {
			rv = -2;
			break;
		}
		/* Else fall through to one of the other strategies... */
		drbd_warn(peer_device, "Discard younger/older primary did not find a decision\n"
			  "Using discard-least-changes instead\n");
	case ASB_DISCARD_ZERO_CHG:
		if (ch_peer == 0 && ch_self == 0) {
			rv = test_bit(RESOLVE_CONFLICTS, &peer_device->connection->transport.flags)
				? -2 : 2;
			break;
		} else {
			if (ch_peer == 0) { rv =  2; break; }
			if (ch_self == 0) { rv = -2; break; }
		}
		if (after_sb_0p == ASB_DISCARD_ZERO_CHG)
			break;
	case ASB_DISCARD_LEAST_CHG:
		if	(ch_self < ch_peer)
			rv = -2;
		else if (ch_self > ch_peer)
			rv =  2;
		else /* ( ch_self == ch_peer ) */
		     /* Well, then use something else. */
			rv = test_bit(RESOLVE_CONFLICTS, &peer_device->connection->transport.flags)
				? -2 : 2;
		break;
	case ASB_DISCARD_LOCAL:
		rv = -2;
		break;
	case ASB_DISCARD_REMOTE:
		rv =  2;
	}

	return rv;
}

/**
 * drbd_asb_recover_1p  -  Recover after split-brain with one remaining primary
 */
static int drbd_asb_recover_1p(struct drbd_peer_device *peer_device) __must_hold(local)
{
	struct drbd_device *device = peer_device->device;
	struct drbd_connection *connection = peer_device->connection;
	struct drbd_resource *resource = device->resource;
	int hg, rv = -100;
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
		drbd_err(device, "Configuration error.\n");
		break;
	case ASB_DISCONNECT:
		break;
	case ASB_CONSENSUS:
		hg = drbd_asb_recover_0p(peer_device);
		if (hg == -2 && resource->role[NOW] == R_SECONDARY)
			rv = hg;
		if (hg ==  2 && resource->role[NOW] == R_PRIMARY)
			rv = hg;
		break;
	case ASB_VIOLENTLY:
		rv = drbd_asb_recover_0p(peer_device);
		break;
	case ASB_DISCARD_SECONDARY:
		return resource->role[NOW] == R_PRIMARY ? 2 : -2;
	case ASB_CALL_HELPER:
		hg = drbd_asb_recover_0p(peer_device);
		if (hg == -2 && resource->role[NOW] == R_PRIMARY) {
			enum drbd_state_rv rv2;

			 /* drbd_change_state() does not sleep while in SS_IN_TRANSIENT_STATE,
			  * we might be here in L_OFF which is transient.
			  * we do not need to wait for the after state change work either. */
			rv2 = change_role(resource, R_SECONDARY, CS_VERBOSE, false);
			if (rv2 != SS_SUCCESS) {
				drbd_khelper(device, connection, "pri-lost-after-sb");
			} else {
				drbd_warn(device, "Successfully gave up primary role.\n");
				rv = hg;
			}
		} else
			rv = hg;
	}

	return rv;
}

/**
 * drbd_asb_recover_2p  -  Recover after split-brain with two remaining primaries
 */
static int drbd_asb_recover_2p(struct drbd_peer_device *peer_device) __must_hold(local)
{
	struct drbd_device *device = peer_device->device;
	struct drbd_connection *connection = peer_device->connection;
	int hg, rv = -100;
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
		drbd_err(device, "Configuration error.\n");
		break;
	case ASB_VIOLENTLY:
		rv = drbd_asb_recover_0p(peer_device);
		break;
	case ASB_DISCONNECT:
		break;
	case ASB_CALL_HELPER:
		hg = drbd_asb_recover_0p(peer_device);
		if (hg == -2) {
			enum drbd_state_rv rv2;

			 /* drbd_change_state() does not sleep while in SS_IN_TRANSIENT_STATE,
			  * we might be here in L_OFF which is transient.
			  * we do not need to wait for the after state change work either. */
			rv2 = change_role(device->resource, R_SECONDARY, CS_VERBOSE, false);
			if (rv2 != SS_SUCCESS) {
				drbd_khelper(device, connection, "pri-lost-after-sb");
			} else {
				drbd_warn(device, "Successfully gave up primary role.\n");
				rv = hg;
			}
		} else
			rv = hg;
	}

	return rv;
}

static void drbd_uuid_dump_self(struct drbd_peer_device *peer_device, u64 bits, u64 flags)
{
	struct drbd_device *device = peer_device->device;

	drbd_info(peer_device, "self %016llX:%016llX:%016llX:%016llX bits:%llu flags:%llX\n",
		  (unsigned long long)drbd_current_uuid(peer_device->device),
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

static int uuid_fixup_resync_end(struct drbd_peer_device *peer_device, int *rule_nr) __must_hold(local)
{
	struct drbd_device *device = peer_device->device;
	const int node_id = device->resource->res_opts.node_id;

	if (peer_device->bitmap_uuids[node_id] == (u64)0 && drbd_bitmap_uuid(peer_device) != (u64)0) {

		if (peer_device->connection->agreed_pro_version < 91)
			return -1091;

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

		return 2;
	}

	if (drbd_bitmap_uuid(peer_device) == (u64)0 && peer_device->bitmap_uuids[node_id] != (u64)0) {

		if (peer_device->connection->agreed_pro_version < 91)
			return -1091;

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

		return -2;
	}

	return -2000;
}

static int uuid_fixup_resync_start1(struct drbd_peer_device *peer_device, int *rule_nr) __must_hold(local)
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
				return -1091;

			peer_device->bitmap_uuids[node_id] = peer_device->history_uuids[0];
			for (i = 0; i < ARRAY_SIZE(peer_device->history_uuids) - 1; i++)
				peer_device->history_uuids[i] = peer_device->history_uuids[i + 1];
			peer_device->history_uuids[i] = 0;

			drbd_info(device, "Lost last syncUUID packet, corrected:\n");
			drbd_uuid_dump_peer(peer_device, peer_device->dirty_bits, peer_device->uuid_flags);

			return -2;
		}
	}

	return -2000;
}

static int uuid_fixup_resync_start2(struct drbd_peer_device *peer_device, int *rule_nr) __must_hold(local)
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
				return -1091;

			bitmap_uuid = _drbd_uuid_pull_history(peer_device);
			__drbd_uuid_set_bitmap(peer_device, bitmap_uuid);

			drbd_info(device, "Last syncUUID did not get through, corrected:\n");
			drbd_uuid_dump_self(peer_device,
					    device->disk_state[NOW] >= D_NEGOTIATING ? drbd_bm_total_weight(peer_device) : 0, 0);

			return 2;
		}
	}

	return -2000;
}

/*
  100	after split brain try auto recover
    4   L_SYNC_SOURCE copy BitMap from
    3	L_SYNC_SOURCE set BitMap
    2	L_SYNC_SOURCE use BitMap
    1   L_SYNC_SOURCE use BitMap, if it was a common power failure
    0	no Sync
   -1   L_SYNC_TARGET use BitMap, it if was a common power failure
   -2	L_SYNC_TARGET use BitMap
   -3	L_SYNC_TARGET set BitMap
   -4   L_SYNC_TARGET clear BitMap
 -100	after split brain, disconnect
-1000	unrelated data
-1091   requires proto 91
-1096   requires proto 96
 */
static int drbd_uuid_compare(struct drbd_peer_device *peer_device,
			     int *rule_nr, int *peer_node_id) __must_hold(local)
{
	struct drbd_connection *connection = peer_device->connection;
	struct drbd_device *device = peer_device->device;
	const int node_id = device->resource->res_opts.node_id;
	u64 self, peer;
	int i, j;

	self = drbd_current_uuid(device) & ~UUID_PRIMARY;
	peer = peer_device->current_uuid & ~UUID_PRIMARY;

	/* Before DRBD 8.0.2 (from 2007), the uuid on sync targets was set to
	 * zero during resyncs for no good reason. */
	if (self == 0)
		self = UUID_JUST_CREATED;
	if (peer == 0)
		peer = UUID_JUST_CREATED;

	*rule_nr = 10;
	if (self == UUID_JUST_CREATED && peer == UUID_JUST_CREATED)
		return 0;

	*rule_nr = 20;
	if (self == UUID_JUST_CREATED)
		return -3;

	*rule_nr = 30;
	if (peer == UUID_JUST_CREATED)
		return 3;

	if (self == peer) {
		if (connection->agreed_pro_version < 110) {
			int rv = uuid_fixup_resync_end(peer_device, rule_nr);
			if (rv > -2000)
				return rv;
		}

		*rule_nr = 35;
		/* Peer crashed as primary, I survived, resync from me */
		if (peer_device->uuid_flags & UUID_FLAG_CRASHED_PRIMARY &&
		    test_bit(RECONNECT, &peer_device->connection->flags))
			return 1;

		/* I am a crashed primary, peer survived, resync to me */
		if (test_bit(CRASHED_PRIMARY, &device->flags) &&
		    peer_device->uuid_flags & UUID_FLAG_RECONNECT)
			return -1;

		/* One of us had a connection to the other node before.
		   i.e. this is not a common power failure. */
		if (peer_device->uuid_flags & UUID_FLAG_RECONNECT ||
		    test_bit(RECONNECT, &peer_device->connection->flags))
			return 0;

		/* Common power [off|failure]? */
		*rule_nr = 40;
		if (test_bit(CRASHED_PRIMARY, &device->flags)) {
			if ((peer_device->uuid_flags & UUID_FLAG_CRASHED_PRIMARY) &&
			    test_bit(RESOLVE_CONFLICTS, &connection->transport.flags))
				return -1;
			return 1;
		} else if (peer_device->uuid_flags & UUID_FLAG_CRASHED_PRIMARY)
				return -1;
		else
			return 0;
	}

	*rule_nr = 50;
	peer = peer_device->bitmap_uuids[node_id] & ~UUID_PRIMARY;
	if (self == peer)
		return -2;

	*rule_nr = 52;
	for (i = 0; i < DRBD_PEERS_MAX; i++) {
		peer = peer_device->bitmap_uuids[i] & ~UUID_PRIMARY;
		if (self == peer) {
			*peer_node_id = i;
			return -4;
		}
	}

	if (connection->agreed_pro_version < 110) {
		int rv = uuid_fixup_resync_start1(peer_device, rule_nr);
		if (rv > -2000)
			return rv;
	}

	*rule_nr = 60;
	self = drbd_current_uuid(device) & ~UUID_PRIMARY;
	for (i = 0; i < ARRAY_SIZE(peer_device->history_uuids); i++) {
		peer = peer_device->history_uuids[i] & ~UUID_PRIMARY;
		if (self == peer)
			return -3;
	}

	*rule_nr = 70;
	self = drbd_bitmap_uuid(peer_device) & ~UUID_PRIMARY;
	peer = peer_device->current_uuid & ~UUID_PRIMARY;
	if (self == peer)
		return 2;

	*rule_nr = 72;
	for (i = 0; i < DRBD_NODE_ID_MAX; i++) {
		if (i == peer_device->node_id)
			continue;
		if (i == device->ldev->md.node_id)
			continue;
		self = device->ldev->md.peers[i].bitmap_uuid & ~UUID_PRIMARY;
		if (self == peer) {
			*peer_node_id = i;
			return 4;
		}
	}

	if (connection->agreed_pro_version < 110) {
		int rv = uuid_fixup_resync_start2(peer_device, rule_nr);
		if (rv > -2000)
			return rv;
	}

	*rule_nr = 80;
	peer = peer_device->current_uuid & ~UUID_PRIMARY;
	for (i = 0; i < HISTORY_UUIDS; i++) {
		self = drbd_history_uuid(device, i) & ~UUID_PRIMARY;
		if (self == peer)
			return 3;
	}

	*rule_nr = 90;
	self = drbd_bitmap_uuid(peer_device) & ~UUID_PRIMARY;
	peer = peer_device->bitmap_uuids[node_id] & ~UUID_PRIMARY;
	if (self == peer && self != ((u64)0))
		return 100;

	*rule_nr = 100;
	for (i = 0; i < HISTORY_UUIDS; i++) {
		self = drbd_history_uuid(device, i) & ~UUID_PRIMARY;
		for (j = 0; j < ARRAY_SIZE(peer_device->history_uuids); j++) {
			peer = peer_device->history_uuids[j] & ~UUID_PRIMARY;
			if (self == peer)
				return -100;
		}
	}

	return -1000;
}

static void log_handshake(struct drbd_peer_device *peer_device)
{
	drbd_info(peer_device, "drbd_sync_handshake:\n");
	drbd_uuid_dump_self(peer_device, peer_device->comm_bm_set, 0);
	drbd_uuid_dump_peer(peer_device, peer_device->dirty_bits, peer_device->uuid_flags);
}

static int drbd_handshake(struct drbd_peer_device *peer_device,
			  int *rule_nr,
			  int *peer_node_id,
			  bool always_verbose) __must_hold(local)
{
	struct drbd_device *device = peer_device->device;
	int hg;

	spin_lock_irq(&device->ldev->md.uuid_lock);
	if (always_verbose)
		log_handshake(peer_device);

	hg = drbd_uuid_compare(peer_device, rule_nr, peer_node_id);
	if (hg && !always_verbose)
		log_handshake(peer_device);
	spin_unlock_irq(&device->ldev->md.uuid_lock);

	if (hg || always_verbose)
		drbd_info(peer_device, "uuid_compare()=%d by rule %d\n", hg, *rule_nr);

	return hg;
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

static int bitmap_mod_after_handshake(struct drbd_peer_device *peer_device, int hg, int peer_node_id)
{
	struct drbd_device *device = peer_device->device;

	if (hg == 4) {
		int from = device->ldev->md.peers[peer_node_id].bitmap_index;

		if (from == -1)
			return 0;

		drbd_info(peer_device, "Peer synced up with node %d, copying bitmap\n", peer_node_id);
		drbd_suspend_io(device, WRITE_ONLY);
		drbd_bm_slot_lock(peer_device, "bm_copy_slot from sync_handshake", BM_LOCK_BULK);
		drbd_bm_copy_slot(device, from, peer_device->bitmap_index);
		drbd_bm_write(device, NULL);
		drbd_bm_slot_unlock(peer_device);
		drbd_resume_io(device);
	} else if (hg == -4) {
		drbd_info(peer_device, "synced up with node %d in the mean time\n", peer_node_id);
		drbd_suspend_io(device, WRITE_ONLY);
		drbd_bm_slot_lock(peer_device, "bm_clear_many_bits from sync_handshake", BM_LOCK_BULK);
		drbd_bm_clear_many_bits(peer_device, 0, -1UL);
		drbd_bm_write(device, NULL);
		drbd_bm_slot_unlock(peer_device);
		drbd_resume_io(device);
	} else if (abs(hg) >= 3) {
		if (hg == -3 &&
		    drbd_current_uuid(device) == UUID_JUST_CREATED &&
		    is_resync_running(device))
			return 0;

		drbd_info(peer_device,
			  "Writing the whole bitmap, full sync required after drbd_sync_handshake.\n");
		if (drbd_bitmap_io(device, &drbd_bmio_set_n_write, "set_n_write from sync_handshake",
					BM_LOCK_CLEAR | BM_LOCK_BULK, peer_device))
			return -1;
	}
	return 0;
}

static enum drbd_repl_state goodness_to_repl_state(struct drbd_peer_device *peer_device,
						   enum drbd_role peer_role,
						   int hg)
{
	struct drbd_device *device = peer_device->device;
	enum drbd_role role = peer_device->device->resource->role[NOW];
	enum drbd_repl_state rv;

	if (hg == 1 || hg == -1) {
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

	if (hg > 0) { /* become sync source. */
		rv = L_WF_BITMAP_S;
	} else if (hg < 0) { /* become sync target */
		rv = L_WF_BITMAP_T;
	} else {
		rv = L_ESTABLISHED;
		if (drbd_bitmap_uuid(peer_device)) {
			drbd_info(peer_device, "clearing bitmap UUID and bitmap content (%lu bits)\n",
				  drbd_bm_total_weight(peer_device));
			drbd_uuid_set_bitmap(peer_device, 0);
			drbd_bm_clear_many_bits(peer_device, 0, -1UL);
		} else if (drbd_bm_total_weight(peer_device)) {
			drbd_info(device, "No resync, but %lu bits in bitmap!\n",
				  drbd_bm_total_weight(peer_device));
		}
	}

	return rv;
}

static void disk_states_to_goodness(struct drbd_device *device,
				    enum drbd_disk_state peer_disk_state,
				    int *hg)
{
	enum drbd_disk_state disk_state = device->disk_state[NOW];

	if (*hg != 0)
		return;

	if (disk_state == D_NEGOTIATING)
		disk_state = disk_state_from_md(device);

	if ((disk_state == D_INCONSISTENT && peer_disk_state > D_INCONSISTENT) ||
	    (peer_disk_state == D_INCONSISTENT && disk_state > D_INCONSISTENT)) {
		*hg = disk_state > D_INCONSISTENT ? 1 : -1;
		drbd_info(device, "Becoming sync %s due to disk states.\n",
			  *hg > 0 ? "source" : "target");
	}
}

static enum drbd_repl_state drbd_attach_handshake(struct drbd_peer_device *peer_device,
						  enum drbd_disk_state peer_disk_state) __must_hold(local)
{
	int hg, rule_nr, peer_node_id;

	hg = drbd_handshake(peer_device, &rule_nr, &peer_node_id, true);

	if (hg < -4 || hg > 4)
		return -1;

	bitmap_mod_after_handshake(peer_device, hg, peer_node_id);
	disk_states_to_goodness(peer_device->device, peer_disk_state, &hg);

	return goodness_to_repl_state(peer_device, peer_device->connection->peer_role[NOW], hg);
}

/* drbd_sync_handshake() returns the new replication state on success, and -1
 * on failure.
 */
static enum drbd_repl_state drbd_sync_handshake(struct drbd_peer_device *peer_device,
						enum drbd_role peer_role,
						enum drbd_disk_state peer_disk_state) __must_hold(local)
{
	struct drbd_device *device = peer_device->device;
	struct drbd_connection *connection = peer_device->connection;
	enum drbd_disk_state disk_state;
	struct net_conf *nc;
	int hg, rule_nr, rr_conflict, peer_node_id = 0, r;

	hg = drbd_handshake(peer_device, &rule_nr, &peer_node_id, true);

	disk_state = device->disk_state[NOW];
	if (disk_state == D_NEGOTIATING)
		disk_state = disk_state_from_md(device);

	if (hg == -1000) {
		drbd_alert(device, "Unrelated data, aborting!\n");
		return -1;
	}
	if (hg < -1000) {
		drbd_alert(device, "To resolve this both sides have to support at least protocol %d\n", -hg - 1000);
		return -1;
	}

	disk_states_to_goodness(device, peer_disk_state, &hg);

	if (abs(hg) == 100)
		drbd_khelper(device, connection, "initial-split-brain");

	rcu_read_lock();
	nc = rcu_dereference(connection->transport.net_conf);

	if (hg == 100 || (hg == -100 && nc->always_asbp)) {
		int pcount = (device->resource->role[NOW] == R_PRIMARY)
			   + (peer_role == R_PRIMARY);
		int forced = (hg == -100);

		switch (pcount) {
		case 0:
			hg = drbd_asb_recover_0p(peer_device);
			break;
		case 1:
			hg = drbd_asb_recover_1p(peer_device);
			break;
		case 2:
			hg = drbd_asb_recover_2p(peer_device);
			break;
		}
		if (abs(hg) < 100) {
			drbd_warn(device, "Split-Brain detected, %d primaries, "
			     "automatically solved. Sync from %s node\n",
			     pcount, (hg < 0) ? "peer" : "this");
			if (forced) {
				drbd_warn(device, "Doing a full sync, since"
				     " UUIDs where ambiguous.\n");
				hg = hg + (hg > 0 ? 1 : -1);
			}
		}
	}

	if (hg == -100) {
		if (test_bit(DISCARD_MY_DATA, &device->flags) &&
		    !(peer_device->uuid_flags & UUID_FLAG_DISCARD_MY_DATA))
			hg = -2;
		if (!test_bit(DISCARD_MY_DATA, &device->flags) &&
		    (peer_device->uuid_flags & UUID_FLAG_DISCARD_MY_DATA))
			hg = 2;

		if (abs(hg) < 100)
			drbd_warn(device, "Split-Brain detected, manually solved. "
			     "Sync from %s node\n",
			     (hg < 0) ? "peer" : "this");
	}
	rr_conflict = nc->rr_conflict;
	rcu_read_unlock();

	if (hg == -100) {
		drbd_alert(device, "Split-Brain detected but unresolved, dropping connection!\n");
		drbd_khelper(device, connection, "split-brain");
		return -1;
	}

	if (hg <= -2 && /* by intention we do not use disk_state here. */
	    device->resource->role[NOW] == R_PRIMARY && device->disk_state[NOW] >= D_CONSISTENT) {
		switch (rr_conflict) {
		case ASB_CALL_HELPER:
			drbd_khelper(device, connection, "pri-lost");
			/* fall through */
		case ASB_DISCONNECT:
			drbd_err(device, "I shall become SyncTarget, but I am primary!\n");
			return -1;
		case ASB_VIOLENTLY:
			drbd_warn(device, "Becoming SyncTarget, violating the stable-data"
			     "assumption\n");
		}
	}

	if (test_bit(CONN_DRY_RUN, &connection->flags)) {
		if (hg == 0)
			drbd_info(device, "dry-run connect: No resync, would become Connected immediately.\n");
		else
			drbd_info(device, "dry-run connect: Would become %s, doing a %s resync.",
				 drbd_repl_str(hg > 0 ? L_SYNC_SOURCE : L_SYNC_TARGET),
				 abs(hg) >= 2 ? "full" : "bit-map based");
		return -1;
	}

	r = bitmap_mod_after_handshake(peer_device, hg, peer_node_id);
	if (r)
		return r;

	return goodness_to_repl_state(peer_device, peer_role, hg);
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
	struct crypto_hash *peer_integrity_tfm = NULL;
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

		peer_integrity_tfm = crypto_alloc_hash(integrity_alg, 0, CRYPTO_ALG_ASYNC);
		if (!peer_integrity_tfm) {
			drbd_err(connection, "peer data-integrity-alg %s not supported\n",
				 integrity_alg);
			goto disconnect;
		}

		hash_size = crypto_hash_digestsize(peer_integrity_tfm);
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

	crypto_free_hash(connection->peer_integrity_tfm);
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
	crypto_free_hash(peer_integrity_tfm);
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
static struct crypto_hash *drbd_crypto_alloc_digest_safe(const struct drbd_device *device,
		const char *alg, const char *name)
{
	struct crypto_hash *tfm;

	if (!alg[0])
		return NULL;

	tfm = crypto_alloc_hash(alg, 0, CRYPTO_ALG_ASYNC);
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
	struct crypto_hash *verify_tfm = NULL;
	struct crypto_hash *csums_tfm = NULL;
	struct net_conf *old_net_conf, *new_net_conf = NULL;
	struct peer_device_conf *old_peer_device_conf = NULL, *new_peer_device_conf = NULL;
	const int apv = connection->agreed_pro_version;
	struct fifo_buffer *old_plan = NULL, *new_plan = NULL;
	struct drbd_resource *resource = connection->resource;
	int fifo_size = 0;
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
				err = -EIO;
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

			fifo_size = (new_peer_device_conf->c_plan_ahead * 10 * SLEEP_TIME) / HZ;
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
				crypto_free_hash(connection->verify_tfm);
				connection->verify_tfm = verify_tfm;
				drbd_info(device, "using verify-alg: \"%s\"\n", p->verify_alg);
			}
			if (csums_tfm) {
				strcpy(new_net_conf->csums_alg, p->csums_alg);
				new_net_conf->csums_alg_len = strlen(p->csums_alg) + 1;
				crypto_free_hash(connection->csums_tfm);
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
	crypto_free_hash(csums_tfm);
	/* but free the verify_tfm again, if csums_tfm did not work out */
	crypto_free_hash(verify_tfm);
	change_cstate(connection, C_DISCONNECTING, CS_HARD);
	return -EIO;
}

static void drbd_setup_order_type(struct drbd_device *device, int peer)
{
	/* sorry, we currently have no working implementation
	 * of distributed TCQ */
}

/* warn if the arguments differ by more than 12.5% */
static void warn_if_differ_considerably(struct drbd_device *device,
	const char *s, sector_t a, sector_t b)
{
	sector_t d;
	if (a == 0 || b == 0)
		return;
	d = (a > b) ? (a - b) : (b - a);
	if (d > (a>>3) || d > (b>>3))
		drbd_warn(device, "Considerable difference in %s: %llus vs. %llus\n", s,
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

static int receive_sizes(struct drbd_connection *connection, struct packet_info *pi)
{
	struct drbd_peer_device *peer_device;
	struct drbd_device *device;
	struct p_sizes *p = pi->data;
	enum determine_dev_size dd = DS_UNCHANGED;
	int ldsc = 0; /* local disk size changed */
	enum dds_flags ddsf;
	unsigned int protocol_max_bio_size;
	bool have_ldev = false;
	int err;

	peer_device = conn_peer_device(connection, pi->vnr);
	if (!peer_device)
		return config_unknown_volume(connection, pi);
	device = peer_device->device;

	/* just store the peer's disk size for now.
	 * we still need to figure out whether we accept that. */
	/* In case I am diskless, need to accept the peer's *current* size.
	 *
	 * At this point, the peer knows more about my disk, or at
	 * least about what we last agreed upon, than myself.
	 * So if his c_size is less than his d_size, the most likely
	 * reason is that *my* d_size was smaller last time we checked.
	 *
	 * However, if he sends a zero current size,
	 * take his (user-capped or) backing disk size anyways.
	 */
	peer_device->max_size =
		be64_to_cpu(p->c_size) ?: be64_to_cpu(p->u_size) ?: be64_to_cpu(p->d_size);

	if (get_ldev(device)) {
		sector_t p_usize = be64_to_cpu(p->u_size), my_usize;

		have_ldev = true;

		rcu_read_lock();
		my_usize = rcu_dereference(device->ldev->disk_conf)->disk_size;
		rcu_read_unlock();

		warn_if_differ_considerably(device, "lower level device sizes",
			   peer_device->max_size, drbd_get_max_capacity(device->ldev));
		warn_if_differ_considerably(device, "user requested size",
					    p_usize, my_usize);

		/* if this is the first connect, or an otherwise expected
		 * param exchange, choose the minimum */
		if (peer_device->repl_state[NOW] == L_OFF)
			p_usize = min_not_zero(my_usize, p_usize);

		/* Never shrink a device with usable data during connect.
		   But allow online shrinking if we are connected. */
		if (drbd_new_dev_size(device, p_usize, 0) <
		    drbd_get_capacity(device->this_bdev) &&
		    device->disk_state[NOW] >= D_OUTDATED &&
		    peer_device->repl_state[NOW] < L_ESTABLISHED) {
			drbd_err(device, "The peer's disk size is too small!\n");
			change_cstate(connection, C_DISCONNECTING, CS_HARD);
			err = -EIO;
			goto out;
		}

		if (my_usize != p_usize) {
			struct disk_conf *old_disk_conf, *new_disk_conf;

			new_disk_conf = kzalloc(sizeof(struct disk_conf), GFP_KERNEL);
			if (!new_disk_conf) {
				drbd_err(device, "Allocation of new disk_conf failed\n");
				err = -ENOMEM;
				goto out;
			}

			err = mutex_lock_interruptible(&connection->resource->conf_update);
			if (err) {
				drbd_err(connection, "Interrupted while waiting for conf_update\n");
				goto out;
			}
			old_disk_conf = device->ldev->disk_conf;
			*new_disk_conf = *old_disk_conf;
			new_disk_conf->disk_size = p_usize;

			rcu_assign_pointer(device->ldev->disk_conf, new_disk_conf);
			mutex_unlock(&connection->resource->conf_update);
			synchronize_rcu();
			kfree(old_disk_conf);

			drbd_info(device, "Peer sets u_size to %lu sectors\n",
				 (unsigned long)my_usize);
		}
	}

	/* The protocol version limits how big requests can be.  In addition,
	 * peers before protocol version 94 cannot split large requests into
	 * multiple bios; their reported max_bio_size is a hard limit.
	 */
	protocol_max_bio_size = conn_max_bio_size(connection);
	peer_device->max_bio_size = min(be32_to_cpu(p->max_bio_size), protocol_max_bio_size);
	ddsf = be16_to_cpu(p->dds_flags);

	/* Leave drbd_reconsider_max_bio_size() before drbd_determine_dev_size().
	   In case we cleared the QUEUE_FLAG_DISCARD from our queue in
	   drbd_reconsider_max_bio_size(), we can be sure that after
	   drbd_determine_dev_size() no REQ_DISCARDs are in the queue. */
	if (have_ldev) {
		drbd_reconsider_max_bio_size(device, device->ldev);
		dd = drbd_determine_dev_size(device, ddsf, NULL);
		if (dd == DS_ERROR) {
			err = -EIO;
			goto out;
		}
		drbd_md_sync(device);
	} else {
		struct drbd_peer_device *peer_device;
		sector_t size = 0;

		drbd_reconsider_max_bio_size(device, NULL);
		/* I am diskless, need to accept the peer disk sizes. */

		rcu_read_lock();
		for_each_peer_device_rcu(peer_device, device) {
			/* When a peer device is in L_OFF state, max_size is zero
			 * until a P_SIZES packet is received.  */
			size = min_not_zero(size, peer_device->max_size);
		}
		rcu_read_unlock();
		if (size)
			drbd_set_my_capacity(device, size);
	}

	if (device->device_conf.max_bio_size > protocol_max_bio_size ||
	    (connection->agreed_pro_version < 94 &&
	     device->device_conf.max_bio_size > peer_device->max_bio_size)) {
		drbd_err(device, "Peer cannot deal with requests bigger than %u. "
			 "Please reduce max_bio_size in the configuration.\n",
			 peer_device->max_bio_size);
		change_cstate(connection, C_DISCONNECTING, CS_HARD);
		err = -EIO;
		goto out;
	}

	if (have_ldev) {
		if (device->ldev->known_size != drbd_get_capacity(device->ldev->backing_bdev)) {
			device->ldev->known_size = drbd_get_capacity(device->ldev->backing_bdev);
			ldsc = 1;
		}

		drbd_setup_order_type(device, be16_to_cpu(p->queue_order_type));
	}

	if (peer_device->repl_state[NOW] > L_OFF) {
		if (be64_to_cpu(p->c_size) !=
		    drbd_get_capacity(device->this_bdev) || ldsc) {
			/* we have different sizes, probably peer
			 * needs to know my new size... */
			drbd_send_sizes(peer_device, 0, ddsf);
		}
		if (test_and_clear_bit(RESIZE_PENDING, &peer_device->flags) ||
		    (dd == DS_GREW && peer_device->repl_state[NOW] == L_ESTABLISHED)) {
			if (peer_device->disk_state[NOW] >= D_INCONSISTENT &&
			    device->disk_state[NOW] >= D_INCONSISTENT) {
				if (ddsf & DDSF_NO_RESYNC)
					drbd_info(device, "Resync of new storage suppressed with --assume-clean\n");
				else
					resync_after_online_grow(peer_device);
			} else
				set_bit(RESYNC_AFTER_NEG, &peer_device->flags);
		}
	}
	err = 0;

out:
	if (have_ldev)
		put_ldev(device);
	return err;
}

void drbd_resync_after_unstable(struct drbd_peer_device *peer_device) __must_hold(local)
{
	enum drbd_role peer_role = peer_device->connection->peer_role[NOW];
	enum drbd_repl_state new_repl_state;
	int hg, rule_nr, peer_node_id;
	enum drbd_state_rv rv;

	hg = drbd_handshake(peer_device, &rule_nr, &peer_node_id, false);
	new_repl_state = hg < -4 || hg > 4 ? -1 : goodness_to_repl_state(peer_device, peer_role, hg);

	if (new_repl_state == -1) {
		drbd_info(peer_device, "Unexpected result of handshake() %d!\n", new_repl_state);
		return;
	} else if (new_repl_state != L_ESTABLISHED) {
		bitmap_mod_after_handshake(peer_device, hg, peer_node_id);
		drbd_info(peer_device, "Becoming %s after unstable\n", drbd_repl_str(new_repl_state));
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

static int __receive_uuids(struct drbd_peer_device *peer_device, u64 node_mask)
{
	enum drbd_repl_state repl_state = peer_device->repl_state[NOW];
	struct drbd_device *device = peer_device->device;
	int updated_uuids = 0, err = 0;

	if (repl_state < L_ESTABLISHED &&
	    device->disk_state[NOW] < D_INCONSISTENT &&
	    device->resource->role[NOW] == R_PRIMARY &&
	    (device->exposed_data_uuid & ~UUID_PRIMARY) !=
	    (peer_device->current_uuid & ~UUID_PRIMARY)) {
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
			_drbd_uuid_set_bitmap(peer_device, 0);
			begin_state_change(device->resource, &irq_flags, CS_VERBOSE);
			/* FIXME: Note that req_lock was not taken here before! */
			__change_disk_state(device, D_UP_TO_DATE);
			__change_peer_disk_state(peer_device, D_UP_TO_DATE);
			end_state_change(device->resource, &irq_flags);
			updated_uuids = 1;
		}

		if (peer_device->uuid_flags & UUID_FLAG_NEW_DATAGEN) {
			drbd_warn(peer_device, "received new current UUID: %016llX\n", peer_device->current_uuid);
			drbd_uuid_received_new_current(peer_device, peer_device->current_uuid, node_mask);
		}

		if (device->disk_state[NOW] > D_OUTDATED) {
			int hg, unused_int;
			hg = drbd_uuid_compare(peer_device, &unused_int, &unused_int);

			if (hg == -3 || hg == -2) {
				struct drbd_resource *resource = device->resource;
				unsigned long irq_flags;

				begin_state_change(resource, &irq_flags, CS_VERBOSE);
				if (device->disk_state[NEW] > D_OUTDATED)
					__change_disk_state(device, D_OUTDATED);
				end_state_change(resource, &irq_flags);
			}
		}

		drbd_uuid_detect_finished_resyncs(peer_device);

		drbd_md_sync(device);
		put_ldev(device);
	} else if (device->disk_state[NOW] < D_INCONSISTENT) {
		struct drbd_resource *resource = device->resource;

		spin_lock_irq(&resource->req_lock);
		if (resource->state_change_flags) {
			drbd_info(peer_device, "Delaying update of exposed data uuid\n");
			device->next_exposed_data_uuid = peer_device->current_uuid;
		} else
			updated_uuids = drbd_set_exposed_data_uuid(device, peer_device->current_uuid);
		spin_unlock_irq(&resource->req_lock);

	}

	if (updated_uuids)
		drbd_print_uuids(peer_device, "receiver updated UUIDs to");

	peer_device->uuid_authoritative_nodes =
		peer_device->uuid_flags & UUID_FLAG_STABLE ? 0 : node_mask;

	if ((repl_state == L_SYNC_TARGET || repl_state == L_PAUSED_SYNC_T) &&
	    !(peer_device->uuid_flags & UUID_FLAG_STABLE) &&
	    !drbd_stable_sync_source_present(peer_device, NOW))
		set_bit(UNSTABLE_RESYNC, &peer_device->flags);

	return err;
}

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
	u64 bitmap_uuids_mask;
	struct drbd_peer_md *peer_md = NULL;
	struct drbd_device *device;


	peer_device = conn_peer_device(connection, pi->vnr);
	if (!peer_device)
		return config_unknown_volume(connection, pi);

	device = peer_device->device;

	peer_device->current_uuid = be64_to_cpu(p->current_uuid);
	peer_device->dirty_bits = be64_to_cpu(p->dirty_bits);
	peer_device->uuid_flags = be64_to_cpu(p->uuid_flags);
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
	if (rest && !ignore_remaining_packet(connection, rest))
		return -EIO;

	if (get_ldev(device))
		peer_md = device->ldev->md.peers;
	pos = 0;
	for (i = 0; i < ARRAY_SIZE(peer_device->bitmap_uuids); i++) {
		if (bitmap_uuids_mask & NODE_MASK(i)) {
			peer_device->bitmap_uuids[i] = be64_to_cpu(p->other_uuids[pos++]);
			if (peer_md && peer_md[i].bitmap_index == -1)
				peer_md[i].flags |= MDF_NODE_EXISTS;
		} else {
			peer_device->bitmap_uuids[i] = 0;
		}
	}
	if (peer_md)
		put_ldev(device);

	for (i = 0; i < history_uuids; i++)
		peer_device->history_uuids[i++] = be64_to_cpu(p->other_uuids[pos++]);
	while (i < ARRAY_SIZE(peer_device->history_uuids))
		peer_device->history_uuids[i++] = 0;
	peer_device->uuids_received = true;

	err = __receive_uuids(peer_device, be64_to_cpu(p->node_mask));

	if (peer_device->uuid_flags & UUID_FLAG_GOT_STABLE) {
		struct drbd_device *device = peer_device->device;

		if (peer_device->repl_state[NOW] == L_ESTABLISHED &&
		    drbd_device_stable(device, NULL) && get_ldev(device)) {
			drbd_send_uuids(peer_device, UUID_FLAG_RESYNC, 0);
			drbd_resync_after_unstable(peer_device);
			put_ldev(device);
		}
	}

	if (peer_device->uuid_flags & UUID_FLAG_RESYNC) {
		if (get_ldev(device)) {
			drbd_resync_after_unstable(peer_device);
			put_ldev(device);
		}
	}

	return err;
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
		__change_io_susp_fencing(resource, val.susp_fen);
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
	struct drbd_peer_device *peer_device;
	unsigned long irq_flags;
	enum drbd_state_rv rv;
	int vnr;

	mask = convert_state(mask);
	val = convert_state(val);

	begin_state_change(resource, &irq_flags, flags);
	idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
		rv = __change_peer_device_state(peer_device, mask, val);
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

	rv = end_state_change(resource, &irq_flags);
out:
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
			drbd_md_sync(peer_device->device);
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
		resource->remote_state_change = false;
		resource->twopc_reply.initiator_node_id = -1;
		if (resource->twopc_parent) {
			kref_debug_put(&resource->twopc_parent->kref_debug, 9);
			kref_put(&resource->twopc_parent->kref,
				 drbd_destroy_connection);
			resource->twopc_parent = NULL;
		}
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

void twopc_timer_fn(unsigned long data)
{
	struct drbd_resource *resource = (struct drbd_resource *) data;
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
	if (reply->primary_nodes & ~reply->reachable_nodes) {
		unsigned long irq_flags;

		begin_state_change(resource, &irq_flags, flags);
		__outdate_myself(resource);
		return end_state_change(resource, &irq_flags);
	}

	return SS_NOTHING_TO_DO;
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


static bool when_done_lock(struct drbd_resource *resource)
{
	spin_lock_irq(&resource->req_lock);
	if (!resource->remote_state_change)
		return true;
	spin_unlock_irq(&resource->req_lock);
	return false;
}

static int abort_local_transaction(struct drbd_resource *resource)
{
	long t = twopc_timeout(resource);

	set_bit(TWOPC_ABORT_LOCAL, &resource->flags);
	spin_unlock_irq(&resource->req_lock);
	wake_up(&resource->state_wait);
	t = wait_event_timeout(resource->twopc_wait, when_done_lock(resource), t);
	clear_bit(TWOPC_ABORT_LOCAL, &resource->flags);
	return t ? 0 : -ETIMEDOUT;
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
		    q->reply.initiator_node_id == twopc->initiator_node_id)
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
	struct queued_twopc *q = container_of(w, struct queued_twopc, w);
	struct drbd_connection *connection = q->connection;
	unsigned long t = twopc_timeout(connection->resource) / 4;

	if (jiffies - q->start_jif >= t || cancel) {
		if (!cancel)
			drbd_info(connection, "Rejecting concurrent "
				  "remote state change %u because of "
				  "state change %u takes too long\n",
				  q->reply.tid,
				  connection->resource->twopc_reply.tid);
		drbd_send_twopc_reply(connection, P_TWOPC_RETRY, &q->reply);
	} else {
		process_twopc(connection, &q->reply, &q->packet_info, q->start_jif);
	}

	kref_put(&connection->kref, drbd_destroy_connection);
	kfree(q);

	return 0;
}

void queued_twopc_timer_fn(unsigned long data)
{
	struct drbd_resource *resource = (struct drbd_resource *) data;
	struct queued_twopc *q;
	unsigned long irq_flags;
	unsigned long t = twopc_timeout(resource) / 4;

	spin_lock_irqsave(&resource->queued_twopc_lock, irq_flags);
	q = list_first_entry_or_null(&resource->queued_twopc, struct queued_twopc, w.list);
	if (q) {
		if (jiffies - q->start_jif >= t)
			list_del(&q->w.list);
		else
			q = NULL;
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
		mb();
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
	struct twopc_reply reply;
	int rv;

	reply.vnr = pi->vnr;
	reply.tid = be32_to_cpu(p->tid);
	reply.initiator_node_id = be32_to_cpu(p->initiator_node_id);
	reply.target_node_id = be32_to_cpu(p->target_node_id);
	reply.reachable_nodes = directly_connected_nodes(resource, NOW) |
				NODE_MASK(resource->res_opts.node_id);
	reply.primary_nodes = be64_to_cpu(p->primary_nodes);
	reply.weak_nodes = 0;
	reply.is_disconnect = 0;
	reply.is_aborted = 0;

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
	enum drbd_state_rv rv;
	enum csc_rv csc_rv;

	/* Check for concurrent transactions and duplicate packets. */
	spin_lock_irq(&resource->req_lock);
	resource->starting_queued_twopc = NULL;
	if (reply->is_aborted) {
		spin_unlock_irq(&resource->req_lock);
		return 0;
	}
	csc_rv = check_concurrent_transactions(resource, reply);

	if (csc_rv == CSC_CLEAR) {
		if (pi->cmd != P_TWOPC_PREPARE) {
			/* We have committed or aborted this transaction already. */
			spin_unlock_irq(&resource->req_lock);
			drbd_debug(connection, "Ignoring %s packet %u\n",
				   drbd_packet_name(pi->cmd),
				   reply->tid);
			return 0;
		}
		resource->remote_state_change = true;
	} else if (csc_rv == CSC_MATCH && pi->cmd != P_TWOPC_PREPARE) {
		flags |= CS_PREPARED;
	} else if (csc_rv == CSC_ABORT_LOCAL && pi->cmd == P_TWOPC_PREPARE) {
		int err;

		drbd_info(connection, "Aborting local state change %u to yield to remote "
			  "state change %u.\n",
			  resource->twopc_reply.tid,
			  reply->tid);
		err = abort_local_transaction(resource);
		if (err) {
			/* abort_local_transaction() comes back unlocked if it fails... */
			drbd_info(connection, "Aborting local state change %u "
				  "failed. Rejecting remote state change %u.\n",
				  resource->twopc_reply.tid,
				  reply->tid);
			drbd_send_twopc_reply(connection, P_TWOPC_RETRY, reply);
			return 0;
		}
		resource->remote_state_change = true;
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

		if (pi->cmd == P_TWOPC_PREPARE) {
			if (csc_rv == CSC_QUEUE) {
				int err = queue_twopc(connection, reply, pi);
				if (err)
					goto reject;
			} else if (csc_rv == CSC_TID_MISS) {
				goto reject;
			} else if (csc_rv == CSC_MATCH) {
				/* We have prepared this transaction already. */
				drbd_send_twopc_reply(connection, P_TWOPC_YES, reply);
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
		for_each_connection(affected_connection, resource) {
			/* for_each_connection() protected by holding req_lock here */
			if (reply->initiator_node_id ==
			    affected_connection->peer_node_id)
				goto directly_connected;
		}
		/* only indirectly connected */
		affected_connection = NULL;
		goto next;
	}

    directly_connected:
	if (reply->target_node_id != -1 &&
	    reply->target_node_id != resource->res_opts.node_id) {
		affected_connection = NULL;
		goto next;
	}

	mask.i = be32_to_cpu(p->mask);
	val.i = be32_to_cpu(p->val);

	if (mask.conn == conn_MASK) {
		u64 m = NODE_MASK(reply->initiator_node_id);

		if (val.conn == C_CONNECTED)
			reply->reachable_nodes |= m;
		if (val.conn == C_DISCONNECTING) {
			reply->reachable_nodes &= ~m;
			reply->is_disconnect = 1;
		}
	}

	if (pi->vnr != -1) {
		peer_device = conn_peer_device(affected_connection, pi->vnr);
		/* If we do not know the peer_device, then we are fine with
		   whatever is going on in the cluster. E.g. detach and del-minor
		   one each node, one after the other */

		affected_connection = NULL; /* It is intended for a peer_device! */
	}

    next:
	if (pi->cmd == P_TWOPC_PREPARE) {
		if ((mask.peer == role_MASK && val.peer == R_PRIMARY) ||
		    (mask.peer != role_MASK && resource->role[NOW] == R_PRIMARY)) {
			reply->primary_nodes = NODE_MASK(resource->res_opts.node_id);
			reply->weak_nodes = ~reply->reachable_nodes;
		}
	}

	resource->twopc_reply = *reply;
	spin_unlock_irq(&resource->req_lock);

	switch(pi->cmd) {
	case P_TWOPC_PREPARE:
		drbd_info(connection, "Preparing remote state change %u "
			  "(primary_nodes=%lX, weak_nodes=%lX)\n",
			  reply->tid,
			  (unsigned long)reply->primary_nodes,
			  (unsigned long)reply->weak_nodes);
		flags |= CS_PREPARE;
		break;
	case P_TWOPC_ABORT:
		drbd_info(connection, "Aborting remote state change %u\n",
			  reply->tid);
		flags |= CS_ABORT;
		break;
	default:
		drbd_info(connection, "Committing remote state change %u\n",
			  reply->tid);
		break;
	}

	if (peer_device)
		rv = change_peer_device_state(peer_device, mask, val, flags);
	else if (affected_connection)
		rv = change_connection_state(affected_connection,
					     mask, val, reply, flags | CS_IGN_OUTD_FAIL);
	else
		rv = outdate_if_weak(resource, reply, flags);

	if (flags & CS_PREPARE) {
		spin_lock_irq(&resource->req_lock);
		kref_get(&connection->kref);
		kref_debug_get(&connection->kref_debug, 9);
		resource->twopc_parent = connection;
		mod_timer(&resource->twopc_timer, receive_jif + twopc_timeout(resource));
		spin_unlock_irq(&resource->req_lock);

		if (rv >= SS_SUCCESS) {
			nested_twopc_request(resource, pi->vnr, pi->cmd, p);
		} else {
			enum drbd_packet cmd = (rv == SS_IN_TRANSIENT_STATE) ?
				P_TWOPC_RETRY : P_TWOPC_NO;
			drbd_send_twopc_reply(connection, cmd, reply);
		}
	} else {
		if (flags & CS_PREPARED)
			del_timer(&resource->twopc_timer);

		nested_twopc_request(resource, pi->vnr, pi->cmd, p);
		clear_remote_state_change(resource);

		if (peer_device && rv >= SS_SUCCESS && !(flags & CS_ABORT))
			drbd_md_sync(peer_device->device);

		if (rv >= SS_SUCCESS && !(flags & CS_ABORT)) {
			struct drbd_device *device;
			int vnr;

			if (affected_connection &&
			    mask.conn == conn_MASK && val.conn == C_CONNECTED)
				conn_connect2(connection);

			idr_for_each_entry(&resource->devices, device, vnr) {
				u64 nedu = device->next_exposed_data_uuid;
				if (!nedu)
					continue;
				if (device->disk_state[NOW] < D_INCONSISTENT)
					drbd_set_exposed_data_uuid(device, nedu);
				device->next_exposed_data_uuid = 0;
			}
		}
	}

	return 0;
}

static int receive_state(struct drbd_connection *connection, struct packet_info *pi)
{
	struct drbd_resource *resource = connection->resource;
	struct drbd_peer_device *peer_device = NULL;
	enum drbd_repl_state *repl_state;
	struct drbd_device *device = NULL;
	struct p_state *p = pi->data;
	union drbd_state old_peer_state, peer_state;
	enum drbd_disk_state peer_disk_state;
	enum drbd_repl_state new_repl_state;
	bool peer_was_resync_target;
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
	if (peer_state.disk == D_NEGOTIATING) {
		peer_disk_state = peer_device->uuid_flags & UUID_FLAG_INCONSISTENT ?
			D_INCONSISTENT : D_CONSISTENT;
		drbd_info(device, "real peer disk state = %s\n", drbd_disk_str(peer_disk_state));
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
	    old_peer_state.conn > L_ESTABLISHED && old_peer_state.disk >= D_OUTDATED) {
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
				/* TODO: Since DRBD9 we experience that SyncSource still has
				   bits set... NEED TO UNDERSTAND AND FIX! */
				if (drbd_bm_total_weight(peer_device) > peer_device->rs_failed)
					drbd_warn(peer_device, "SyncSource still sees bits set!! FIXME\n");

				drbd_resync_finished(peer_device, peer_state.disk);
				peer_device->last_repl_state = peer_state.conn;
			}
			return 0;
		}
	}

	/* explicit verify finished notification, stop sector reached. */
	if (old_peer_state.conn == L_VERIFY_T && old_peer_state.disk == D_UP_TO_DATE &&
	    peer_state.conn == C_CONNECTED && peer_disk_state == D_UP_TO_DATE) {
		ov_out_of_sync_print(peer_device);
		drbd_resync_finished(peer_device, D_MASK);
		peer_device->last_repl_state = peer_state.conn;
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

		if (consider_resync) {
			new_repl_state = drbd_sync_handshake(peer_device, peer_state.role, peer_disk_state);
		} else if (old_peer_state.conn == L_ESTABLISHED &&
			   (peer_state.disk == D_NEGOTIATING ||
			    old_peer_state.disk == D_NEGOTIATING)) {
			new_repl_state = drbd_attach_handshake(peer_device, peer_disk_state);
		}

		put_ldev(device);
		if (new_repl_state == -1) {
			new_repl_state = L_ESTABLISHED;
			if (device->disk_state[NOW] == D_NEGOTIATING) {
				new_repl_state = L_NEG_NO_RESULT;
			} else if (peer_state.disk == D_NEGOTIATING) {
				if (connection->agreed_pro_version < 110) {
					drbd_err(device, "Disk attach process on the peer node was aborted.\n");
					peer_state.disk = D_DISKLESS;
					peer_disk_state = D_DISKLESS;
				} else {
					/* The peer will decide later and let us know... */
					peer_disk_state = D_NEGOTIATING;
				}
			} else {
				if (test_and_clear_bit(CONN_DRY_RUN, &connection->flags))
					return -EIO;
				D_ASSERT(device, old_peer_state.conn == L_OFF);
				goto fail;
			}
		}

		if (device->disk_state[NOW] == D_NEGOTIATING) {
			set_bit(NEGOTIATION_RESULT_TOCHED, &resource->flags);
			peer_device->negotiation_result = new_repl_state;
		}
	}

	spin_lock_irq(&resource->req_lock);
	begin_state_change_locked(resource, CS_VERBOSE);
	if (old_peer_state.i != drbd_get_peer_device_state(peer_device, NOW).i) {
		old_peer_state = drbd_get_peer_device_state(peer_device, NOW);
		abort_state_change_locked(resource);
		spin_unlock_irq(&resource->req_lock);
		goto retry;
	}
	clear_bit(CONSIDER_RESYNC, &peer_device->flags);
	if (device->disk_state[NOW] != D_NEGOTIATING)
		__change_repl_state(peer_device, new_repl_state);
	if (connection->peer_role[NOW] == R_UNKNOWN || peer_state.role == R_SECONDARY)
		__change_peer_role(connection, peer_state.role);
	__change_peer_disk_state(peer_device, peer_disk_state);
	__change_resync_susp_peer(peer_device, peer_state.aftr_isp | peer_state.user_isp);
	repl_state = peer_device->repl_state;
	if (repl_state[OLD] < L_ESTABLISHED && repl_state[NEW] >= L_ESTABLISHED)
		resource->state_change_flags |= CS_HARD;
	if (peer_device->disk_state[NEW] == D_CONSISTENT &&
	    drbd_suspended(device) &&
	    repl_state[OLD] < L_ESTABLISHED && repl_state[NEW] == L_ESTABLISHED &&
	    test_and_clear_bit(NEW_CUR_UUID, &device->flags)) {
		unsigned long irq_flags;

		/* Do not allow RESEND for a rebooted peer. We can only allow this
		   for temporary network outages! */
		abort_state_change_locked(resource);
		spin_unlock_irq(&resource->req_lock);

		drbd_err(device, "Aborting Connect, can not thaw IO with an only Consistent peer\n");
		tl_clear(connection);
		mutex_lock(&resource->conf_update);
		drbd_uuid_new_current(device, false);
		mutex_unlock(&resource->conf_update);
		begin_state_change(resource, &irq_flags, CS_HARD);
		__change_cstate(connection, C_PROTOCOL_ERROR);
		__change_io_susp_user(resource, false);
		end_state_change(resource, &irq_flags);
		return -EIO;
	}
	rv = end_state_change_locked(resource);
	new_repl_state = peer_device->repl_state[NOW];
	set_bit(INITIAL_STATE_RECEIVED, &peer_device->flags);
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

	clear_bit(DISCARD_MY_DATA, &device->flags);

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

static enum drbd_disk_state read_disk_state(struct drbd_device *device)
{
	struct drbd_resource *resource = device->resource;
	enum drbd_disk_state disk_state;

	spin_lock_irq(&resource->req_lock);
	disk_state = device->disk_state[NOW];
	spin_unlock_irq(&resource->req_lock);

	return disk_state;
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
	struct drbd_device *device;
	struct bm_xfer_ctx c;
	int err;

	peer_device = conn_peer_device(connection, pi->vnr);
	if (!peer_device)
		return -EIO;
	device = peer_device->device;

	/* Final repl_states become visible when the disk leaves NEGOTIATING state */
	wait_event_interruptible(device->resource->state_wait,
				 read_disk_state(device) != D_NEGOTIATING);

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

	if (peer_device->repl_state[NOW] == L_WF_BITMAP_T) {
		enum drbd_state_rv rv;

		err = drbd_send_bitmap(device, peer_device);
		if (err)
			goto out;
		/* Omit CS_WAIT_COMPLETE and CS_SERIALIZE with this state
		 * transition to avoid deadlocks. */

		if (connection->agreed_pro_version < 110) {
			rv = stable_change_repl_state(peer_device, L_WF_SYNC_UUID, CS_VERBOSE);
			D_ASSERT(device, rv == SS_SUCCESS);
		} else {
			drbd_start_resync(peer_device, L_SYNC_TARGET);
		}
	} else if (peer_device->repl_state[NOW] != L_WF_BITMAP_S) {
		/* admin may have requested C_DISCONNECTING,
		 * other threads may have noticed network errors */
		drbd_info(peer_device, "unexpected repl_state (%s) in receive_bitmap\n",
		    drbd_repl_str(peer_device->repl_state[NOW]));
	}
	err = 0;

 out:
	drbd_bm_slot_unlock(peer_device);
	if (!err && peer_device->repl_state[NOW] == L_WF_BITMAP_S)
		drbd_start_resync(peer_device, L_SYNC_SOURCE);
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

	/* just unplug all devices always, regardless which volume number */
	drbd_unplug_all_devices(connection->resource);

	/* Make sure we've acked all the data associated
	 * with the data requests being unplugged */
	transport->ops->hint(transport, DATA_STREAM, QUICKACK);

	return 0;
}

static int receive_out_of_sync(struct drbd_connection *connection, struct packet_info *pi)
{
	struct drbd_peer_device *peer_device;
	struct drbd_device *device;
	struct p_block_desc *p = pi->data;

	peer_device = conn_peer_device(connection, pi->vnr);
	if (!peer_device)
		return -EIO;
	device = peer_device->device;

	switch (peer_device->repl_state[NOW]) {
	case L_WF_SYNC_UUID:
	case L_WF_BITMAP_T:
	case L_BEHIND:
			break;
	default:
		drbd_err(device, "ASSERT FAILED cstate = %s, expected: WFSyncUUID|WFBitMapT|Behind\n",
				drbd_repl_str(peer_device->repl_state[NOW]));
	}

	drbd_set_out_of_sync(peer_device, be64_to_cpu(p->sector), be32_to_cpu(p->blksize));

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
		if (peer_device->repl_state[NOW] > L_ESTABLISHED)
			goto out;
		if (peer_device->current_uuid != drbd_current_uuid(peer_device->device))
			goto out;
	}

	/* Need to wait until the other receiver thread has called the
	   cleanup_unacked_peer_requests() function */
	wait_event(resource->state_wait,
		   lost_peer->cstate[NOW] <= C_UNCONNECTED || lost_peer->cstate[NOW] == C_CONNECTING);

	dagtag_offset = (s64)lost_peer->last_dagtag_sector - (s64)be64_to_cpu(p->dagtag);
	if (dagtag_offset > 0)
		new_repl_state = L_WF_BITMAP_S;
	else if (dagtag_offset < 0)
		new_repl_state = L_WF_BITMAP_T;
	else
		new_repl_state = L_ESTABLISHED;

	if (new_repl_state != L_ESTABLISHED) {
		unsigned long irq_flags;

		drbd_info(connection, "Reconciliation resync because \'%s\' disappeared. (o=%d)\n",
			  lost_peer->transport.net_conf->name, (int)dagtag_offset);

		begin_state_change(resource, &irq_flags, CS_VERBOSE);
		idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
			__change_repl_state(peer_device, new_repl_state);
			set_bit(RECONCILIATION_RESYNC, &peer_device->flags);
		}
		end_state_change(resource, &irq_flags);
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

/* Accept a new current UUID generated on a diskless node, that just became primary */
static int receive_current_uuid(struct drbd_connection *connection, struct packet_info *pi)
{
	struct drbd_resource *resource = connection->resource;
	struct drbd_peer_device *peer_device;
	struct drbd_device *device;
	struct p_current_uuid *p = pi->data;
	u64 current_uuid, weak_nodes;

	peer_device = conn_peer_device(connection, pi->vnr);
	if (!peer_device)
		return -EIO;
	device = peer_device->device;

	current_uuid = be64_to_cpu(p->uuid);
	weak_nodes = be64_to_cpu(p->weak_nodes);
	if (current_uuid == drbd_current_uuid(device))
		return 0;
	peer_device->current_uuid = current_uuid;

	if (get_ldev(device)) {
		if (connection->peer_role[NOW] == R_PRIMARY) {
			drbd_warn(peer_device, "received new current UUID: %016llX "
				  "weak_nodes=%016llX\n", current_uuid, weak_nodes);
			drbd_uuid_received_new_current(peer_device, current_uuid, weak_nodes);
		}
		put_ldev(device);
	} else if (resource->role[NOW] == R_PRIMARY) {
		drbd_set_exposed_data_uuid(device, peer_device->current_uuid);
	}

	return 0;
}

struct data_cmd {
	int expect_payload;
	size_t pkt_size;
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
	[P_DELAY_PROBE]     = { 0, sizeof(struct p_delay_probe93), receive_skip },
	[P_OUT_OF_SYNC]     = { 0, sizeof(struct p_block_desc), receive_out_of_sync },
	[P_CONN_ST_CHG_REQ] = { 0, sizeof(struct p_req_state), receive_req_state },
	[P_PROTOCOL_UPDATE] = { 1, sizeof(struct p_protocol), receive_protocol },
	[P_TWOPC_PREPARE] = { 0, sizeof(struct p_twopc_request), receive_twopc },
	[P_TWOPC_ABORT] = { 0, sizeof(struct p_twopc_request), receive_twopc },
	[P_DAGTAG]	    = { 0, sizeof(struct p_dagtag), receive_dagtag },
	[P_UUIDS110]	    = { 1, sizeof(struct p_uuids110), receive_uuids110 },
	[P_PEER_DAGTAG]     = { 0, sizeof(struct p_peer_dagtag), receive_peer_dagtag },
	[P_CURRENT_UUID]    = { 0, sizeof(struct p_current_uuid), receive_current_uuid },
	[P_TWOPC_COMMIT]    = { 0, sizeof(struct p_twopc_request), receive_twopc },
	[P_TRIM]	    = { 0, sizeof(struct p_trim), receive_Data },
};

static void drbdd(struct drbd_connection *connection)
{
	struct packet_info pi;
	size_t shs; /* sub header size */
	int err;

	while (get_t_state(&connection->receiver) == RUNNING) {
		struct data_cmd *cmd;

		drbd_thread_current_set_cpu(&connection->receiver);
		update_receiver_timing_details(connection, drbd_recv_header);
		if (drbd_recv_header(connection, &pi))
			goto err_out;

		cmd = &drbd_cmd_handler[pi.cmd];
		if (unlikely(pi.cmd >= ARRAY_SIZE(drbd_cmd_handler) || !cmd->fn)) {
			drbd_err(connection, "Unexpected data packet %s (0x%04x)",
				 drbd_packet_name(pi.cmd), pi.cmd);
			goto err_out;
		}

		shs = cmd->pkt_size;
		if (pi.size > shs && !cmd->expect_payload) {
			drbd_err(connection, "No payload expected %s l:%d\n",
				 drbd_packet_name(pi.cmd), pi.size);
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

void conn_disconnect(struct drbd_connection *connection)
{
	struct drbd_resource *resource = connection->resource;
	struct drbd_peer_device *peer_device;
	enum drbd_conn_state oc;
	unsigned long irq_flags;
	int vnr, i;

	clear_bit(CONN_DRY_RUN, &connection->flags);
	clear_bit(CONN_DISCARD_MY_DATA, &connection->flags);

	if (connection->cstate[NOW] == C_STANDALONE)
		return;

	/* We are about to start the cleanup after connection loss.
	 * Make sure drbd_make_request knows about that.
	 * Usually we should be in some network failure state already,
	 * but just in case we are not, we fix it up here.
	 */
	del_connect_timer(connection);

	change_cstate(connection, C_NETWORK_FAILURE, CS_HARD);

	/* ack_receiver does not clean up anything. it must not interfere, either */
	drbd_thread_stop(&connection->ack_receiver);
	if (connection->ack_sender) {
		destroy_workqueue(connection->ack_sender);
		connection->ack_sender = NULL;
	}

	drbd_transport_shutdown(connection, CLOSE_CONNECTION);
	drbd_drop_unsent(connection);

	rcu_read_lock();
	idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
		struct drbd_device *device = peer_device->device;

		kref_get(&device->kref);
		rcu_read_unlock();
		drbd_disconnected(peer_device);
		kref_put(&device->kref, drbd_destroy_device);
		rcu_read_lock();
	}
	rcu_read_unlock();

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

static int drbd_disconnected(struct drbd_peer_device *peer_device)
{
	struct drbd_device *device = peer_device->device;

	/* wait for current activity to cease. */
	spin_lock_irq(&device->resource->req_lock);
	_drbd_wait_ee_list_empty(device, &device->active_ee);
	_drbd_wait_ee_list_empty(device, &device->sync_ee);
	_drbd_wait_ee_list_empty(device, &device->read_ee);
	spin_unlock_irq(&device->resource->req_lock);

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
	wake_up(&device->misc_wait);

	del_timer_sync(&peer_device->resync_timer);
	resync_timer_fn((unsigned long)peer_device);
	del_timer_sync(&peer_device->start_resync_timer);

	/* wait for all w_e_end_data_req, w_e_end_rsdata_req, w_send_barrier,
	 * w_make_resync_request etc. which may still be on the worker queue
	 * to be "canceled" */
	drbd_flush_workqueue(&peer_device->connection->sender_work);

	drbd_finish_peer_reqs(peer_device);

	/* This second workqueue flush is necessary, since drbd_finish_peer_reqs()
	   might have issued a work again. The one before drbd_finish_peer_reqs() is
	   necessary to reclain net_ee in drbd_finish_peer_reqs(). */
	drbd_flush_workqueue(&peer_device->connection->sender_work);

	/* need to do it again, drbd_finish_peer_reqs() may have populated it
	 * again via drbd_try_clear_on_disk_bm(). */
	drbd_rs_cancel_all(peer_device);

	peer_device->uuids_received = false;

	if (!drbd_suspended(device))
		tl_clear(peer_device->connection);

	drbd_md_sync(device);

	/* serialize with bitmap writeout triggered by the state change,
	 * if any. */
	wait_event(device->misc_wait, !atomic_read(&device->pending_bitmap_work.n));

	/* tcp_close and release of sendpage pages can be deferred.  I don't
	 * want to use SO_LINGER, because apparently it can be deferred for
	 * more than 20 seconds (longest time I checked).
	 *
	 * Actually we don't care for exactly when the network stack does its
	 * put_page(), but release our reference on these pages right here.
	 */

	D_ASSERT(device, list_empty(&device->read_ee));
	D_ASSERT(device, list_empty(&device->active_ee));
	D_ASSERT(device, list_empty(&device->sync_ee));
	D_ASSERT(device, list_empty(&device->done_ee));

	return 0;
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

	p = conn_prepare_command(connection, sizeof(*p), DATA_STREAM);
	if (!p)
		return -EIO;
	memset(p, 0, sizeof(*p));
	p->protocol_min = cpu_to_be32(PRO_VERSION_MIN);
	p->protocol_max = cpu_to_be32(PRO_VERSION_MAX);
	p->sender_node_id = cpu_to_be32(connection->resource->res_opts.node_id);
	p->receiver_node_id = cpu_to_be32(connection->peer_node_id);
	p->feature_flags = cpu_to_be32(PRO_FEATURES);
	return send_command(connection, -1, P_CONNECTION_FEATURES, DATA_STREAM);
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
	if (err)
		return 0;

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
	    PRO_VERSION_MIN > p->protocol_max) {
		drbd_err(connection, "incompatible DRBD dialects: "
		    "I support %d-%d, peer supports %d-%d\n",
		    PRO_VERSION_MIN, PRO_VERSION_MAX,
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

	drbd_info(connection, "Handshake successful: "
	     "Agreed network protocol version %d\n", connection->agreed_pro_version);

	drbd_info(connection, "Agreed to%ssupport TRIM on protocol level\n",
		  connection->agreed_features & FF_TRIM ? " " : " not ");

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
	struct scatterlist sg;
	void *response;
	char *right_response = NULL;
	unsigned int key_len;
	char secret[SHARED_SECRET_MAX]; /* 64 byte */
	unsigned int resp_size;
	struct hash_desc desc;
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

	desc.tfm = connection->cram_hmac_tfm;
	desc.flags = 0;

	rv = crypto_hash_setkey(connection->cram_hmac_tfm, (u8 *)secret, key_len);
	if (rv) {
		drbd_err(connection, "crypto_hash_setkey() failed with %d\n", rv);
		rv = -1;
		goto fail;
	}

	get_random_bytes(my_challenge.d, sizeof(my_challenge.d));

	packet_body = conn_prepare_command(connection, sizeof(my_challenge.d), DATA_STREAM);
	if (!packet_body) {
		rv = 0;
		goto fail;
	}
	memcpy(packet_body, my_challenge.d, sizeof(my_challenge.d));

	rv = !send_command(connection, -1, P_AUTH_CHALLENGE, DATA_STREAM);
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
		rv = 0;
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

	resp_size = crypto_hash_digestsize(connection->cram_hmac_tfm);
	response = conn_prepare_command(connection, resp_size, DATA_STREAM);
	if (!response) {
		rv = 0;
		goto fail;
	}

	sg_init_table(&sg, 1);
	dig_size = pi.size;
	if (peer_is_drbd_9) {
		peers_ch->i = cpu_to_be32(connection->resource->res_opts.node_id);
		dig_size += sizeof(peers_ch->i);
	}
	sg_set_buf(&sg, peers_ch, dig_size);

	rv = crypto_hash_digest(&desc, &sg, sg.length, response);
	if (rv) {
		drbd_err(connection, "crypto_hash_digest() failed with %d\n", rv);
		rv = -1;
		goto fail;
	}

	rv = !send_command(connection, -1, P_AUTH_RESPONSE, DATA_STREAM);
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
		drbd_err(connection, "expected AuthResponse payload of wrong size\n");
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
	sg_set_buf(&sg, &my_challenge, dig_size);

	rv = crypto_hash_digest(&desc, &sg, sg.length, right_response);
	if (rv) {
		drbd_err(connection, "crypto_hash_digest() failed with %d\n", rv);
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

	return rv;
}
#endif

int drbd_receiver(struct drbd_thread *thi)
{
	struct drbd_connection *connection = thi->connection;

	if (conn_connect(connection))
		drbdd(connection);

	conn_disconnect(connection);
	return 0;
}

/* ********* acknowledge sender ******** */

void req_destroy_after_send_peer_ack(struct kref *kref)
{
	struct drbd_request *req = container_of(kref, struct drbd_request, kref);
	list_del(&req->tl_requests);
	mempool_free(req, drbd_request_mempool);
}

static int process_peer_ack_list(struct drbd_connection *connection)
{
	struct drbd_resource *resource = connection->resource;
	struct drbd_request *req, *tmp;
	unsigned int idx;
	int err = 0;

	idx = 1 + connection->peer_node_id;

	spin_lock_irq(&resource->req_lock);
	req = list_first_entry(&resource->peer_ack_list, struct drbd_request, tl_requests);
	while (&req->tl_requests != &resource->peer_ack_list) {
		if (!(req->rq_state[idx] & RQ_PEER_ACK)) {
			req = list_next_entry(req, tl_requests);
			continue;
		}
		req->rq_state[idx] &= ~RQ_PEER_ACK;
		spin_unlock_irq(&resource->req_lock);

		err = drbd_send_peer_ack(connection, req);

		spin_lock_irq(&resource->req_lock);
		tmp = list_next_entry(req, tl_requests);
		kref_put(&req->kref, req_destroy_after_send_peer_ack);
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
	wake_up(&connection->ping_wait);

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
			u64 reachable_nodes =
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
	if (!test_and_set_bit(GOT_PING_ACK, &connection->flags))
		wake_up(&connection->ping_wait);

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
	atomic_add(blksize >> 9, &peer_device->rs_sect_in);

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
		case P_RS_CANCEL:
			bit = BM_SECT_TO_BIT(sector);
			mutex_lock(&device->bm_resync_fo_mutex);
			device->bm_resync_fo = min(device->bm_resync_fo, bit);
			mutex_unlock(&device->bm_resync_fo_mutex);

			atomic_add(size >> 9, &peer_device->rs_sect_in);
			mod_timer(&peer_device->resync_timer, jiffies + SLEEP_TIME);
			break;
		default:
			BUG();
		}
		put_ldev(device);
	}

	return 0;
}

static int got_BarrierAck(struct drbd_connection *connection, struct packet_info *pi)
{
	struct drbd_peer_device *peer_device;
	struct p_barrier_ack *p = pi->data;
	int vnr;

	tl_release(connection, p->barrier, be32_to_cpu(p->set_size));

	rcu_read_lock();
	idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
		struct drbd_device *device = peer_device->device;
		if (peer_device->repl_state[NOW] == L_AHEAD &&
		    atomic_read(&connection->ap_in_flight) == 0 &&
		    !test_and_set_bit(AHEAD_TO_SYNC_SOURCE, &device->flags)) {
			peer_device->start_resync_side = L_SYNC_SOURCE;
			peer_device->start_resync_timer.expires = jiffies + HZ;
			add_timer(&peer_device->start_resync_timer);
		}
	}
	rcu_read_unlock();

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

	--peer_device->ov_left;

	/* let's advance progress step marks only for every other megabyte */
	if ((peer_device->ov_left & 0x200) == 0x200)
		drbd_advance_rs_marks(peer_device, peer_device->ov_left);

	if (peer_device->ov_left == 0) {
		struct drbd_peer_device_work *dw = kmalloc(sizeof(*dw), GFP_NOIO);
		if (dw) {
			dw->w.cb = w_ov_finished;
			dw->peer_device = peer_device;
			drbd_queue_work(&connection->sender_work, &dw->w);
		} else {
			drbd_err(device, "kmalloc(dw) failed.");
			ov_out_of_sync_print(peer_device);
			drbd_resync_finished(peer_device, D_MASK);
		}
	}
	put_ldev(device);
	return 0;
}

static int got_skip(struct drbd_connection *connection, struct packet_info *pi)
{
	return 0;
}

static u64 node_ids_to_bitmap(struct drbd_device *device, u64 node_ids) __must_hold(local)
{
	struct drbd_peer_md *peer_md = device->ldev->md.peers;
	u64 bitmap_bits = 0;
	int node_id;

	for_each_set_bit(node_id, (unsigned long *)&node_ids,
			 sizeof(node_ids) * BITS_PER_BYTE) {
		int bitmap_bit = peer_md[node_id].bitmap_index;
		if (bitmap_bit >= 0)
			bitmap_bits |= NODE_MASK(bitmap_bit);
	}
	return bitmap_bits;
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
		u64 in_sync_b;

		if (get_ldev(device)) {
			in_sync_b = node_ids_to_bitmap(device, in_sync);

			drbd_set_sync(device, peer_req->i.sector,
				      peer_req->i.size, ~in_sync_b, -1);
			put_ldev(device);
		}
		list_del(&peer_req->recv_order);
		drbd_al_complete_io(device, &peer_req->i);
		drbd_free_peer_req(peer_req);
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
		u64 mask = ~(1 << peer_device->bitmap_index);

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
		u64 mask = ~(1 << peer_device->bitmap_index);

		drbd_set_sync(device, peer_req->i.sector, peer_req->i.size,
			      mask, mask);

		list_del(&peer_req->recv_order);
		drbd_al_complete_io(device, &peer_req->i);
		drbd_free_peer_req(peer_req);
	}
}

static void destroy_request(struct kref *kref)
{
	struct drbd_request *req =
		container_of(kref, struct drbd_request, kref);

	list_del(&req->tl_requests);
	mempool_free(req, drbd_request_mempool);
}

static void cleanup_peer_ack_list(struct drbd_connection *connection)
{
	struct drbd_resource *resource = connection->resource;
	struct drbd_request *req, *tmp;
	int idx;

	spin_lock_irq(&resource->req_lock);
	idx = 1 + connection->peer_node_id;
	list_for_each_entry_safe(req, tmp, &resource->peer_ack_list, tl_requests) {
		if (!(req->rq_state[idx] & RQ_PEER_ACK))
			continue;
		req->rq_state[idx] &= ~RQ_PEER_ACK;
		kref_put(&req->kref, destroy_request);
	}
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
	[P_STATE_CHG_REPLY] = { sizeof(struct p_req_state_reply), got_RqSReply },
	[P_RS_IS_IN_SYNC]   = { sizeof(struct p_block_ack), got_IsInSync },
	[P_DELAY_PROBE]     = { sizeof(struct p_delay_probe93), got_skip },
	[P_RS_CANCEL]       = { sizeof(struct p_block_ack), got_NegRSDReply },
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
	struct sched_param param = { .sched_priority = 2 };
	struct drbd_transport *transport = &connection->transport;
	struct drbd_transport_ops *tr_ops = transport->ops;

	rv = sched_setscheduler(current, SCHED_RR, &param);
	if (rv < 0)
		drbd_err(connection, "drbd_ack_receiver: ERROR set priority, ret=%d\n", rv);

	while (get_t_state(thi) == RUNNING) {
		drbd_thread_current_set_cpu(thi);

		drbd_reclaim_net_peer_reqs(connection);

		if (test_and_clear_bit(SEND_PING, &connection->flags)) {
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
			if (test_bit(DISCONNECT_EXPECTED, &connection->flags)) {
				long t;
				rcu_read_lock();
				t = rcu_dereference(connection->transport.net_conf)->ping_timeo * HZ/10;
				rcu_read_unlock();

				t = wait_event_timeout(connection->ping_wait,
						       connection->cstate[NOW] < C_CONNECTED,
						       t);
				if (t)
					break;
			}
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
				drbd_err(connection, "%pf failed\n", cmd->fn);
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
	struct drbd_peer_device *peer_device =
		container_of(ws, struct drbd_peer_device, send_acks_work);
	struct drbd_connection *connection = peer_device->connection;
	struct drbd_transport *transport = &connection->transport;
	struct drbd_device *device = peer_device->device;
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
	err = drbd_finish_peer_reqs(peer_device);
	kref_put(&device->kref, drbd_destroy_device);
	/* get is in drbd_endio_write_sec_final(). That is necessary to keep the
	   struct work_struct send_acks_work alive, which is in the peer_device object */

	/* but unconditionally uncork unless disabled */
	if (tcp_cork)
		drbd_uncork(connection, CONTROL_STREAM);

	if (err)
		change_cstate(connection, C_DISCONNECTING, CS_HARD);

	return;
}

void drbd_send_peer_ack_wf(struct work_struct *ws)
{
	struct drbd_connection *connection =
		container_of(ws, struct drbd_connection, peer_ack_work);

	if (process_peer_ack_list(connection))
		change_cstate(connection, C_DISCONNECTING, CS_HARD);
}

EXPORT_SYMBOL(drbd_alloc_pages); /* for transports */
EXPORT_SYMBOL(drbd_free_pages);
