/*
   drbd_transport_rdma.c

   This file is part of DRBD.

   Copyright (C) 2014, LINBIT HA-Solutions GmbH.

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
#include <drbd_transport.h>
#include <rdma/ib_verbs.h>
#include <rdma/rdma_cm.h>
#include "drbd_int.h"

/* RCK: hack, remove it after connection logic is implemented */
#include <linux/moduleparam.h>
bool rdma_server;
module_param(rdma_server, bool, 0644);

/* RCK:XXX/TODOs:
 * HIGH-LEVEL DESIGN:
 * - discuss what semantics we want to support. There is an interesting read:
 *   http://www.google.at/url?sa=t&rct=j&q=&esrc=s&source=web&cd=1&ved=0CCEQFjAA&url=http%3A%2F%2Fwww.mellanox.com%2Fpdf%2Fwhitepapers%2FWP_Why_Compromise_10_26_06.pdf&ei=VwmHVPXjNsOwPJqcgdgG&usg=AFQjCNFpc5OYdd-h8ylNRUhJjhsILCsZhw&sig2=8MbEQtzOPLpgmL36q6t48Q&bvm=bv.81449611,d.ZWU&cad=rja
 *   google: "rdma infiniband difference send write"
 *   page 5, data transfer semantics. Surprisingly, this favours send/receive.
 *   My limited experience: send/receive is easier, eg. no need to exchange the
 *   rkey. If they are equally fast and rdma write/read is not supported on all
 *   devices, maybe we should stick - at least for the moment - with the easier
 *   to implement send/receive paradigm.
 *
 * IMPLEMENTATION QUIRKS:
 * - Connection logic: implement waiter/listener logic. Currently client/server and streams on different ports
 * - Something is wrong with the post_[rx|tx]_descriptor logic. it always hangs
 *   after the initial descs are used even though that the repost logic looks
 *   OK. CQ has a init_attr.cap.max_send_wr = RDMA_MAX_TX; (same for write).
 *   e.g set the RDMA_MAX/PREALLOC defines to 1024, then it executes relatively
 *   long (until the 1024 are used) Maybe it has something to do with that and
 *   that the descs are still in use for RDMA. too less time to debug and there
 *   will be changes for send/send_page anyways.
 * - module unload currently does not work
 */

MODULE_AUTHOR("Roland Kammerer <roland.kammerer@linbit.com>");
MODULE_AUTHOR("Foo Bar <foo.bar@linbit.com>");
MODULE_DESCRIPTION("RDMA transport layer for DRBD");
MODULE_LICENSE("GPL");

#define RDMA_MAX_RX 1024
#define RDMA_MAX_TX 1024
/* #define RDMA_PREALLOC_RX 1024 */
/* #define RDMA_PREALLOC_TX 1024 */

/* If no recvbuf_size is configured use 512KiB for the DATA_STREAM */
#define RDMA_DEF_RECV_SIZE (1 << 19)

#define RDMA_PAGE_SIZE 4096

enum drbd_rdma_state {
	IDLE = 1,
	CONNECT_REQUEST,
	ADDR_RESOLVED,
	ROUTE_RESOLVED,
	CONNECTED,
	DISCONNECTED,
	ERROR
};

/* RCK: in a next step we should think about the sizes, eg post smaller
 * rx_descs for contol data */
struct drbd_rdma_rx_desc {
	struct page *page;
	char *data;
	u64 dma_addr;
	int size; /* At allocation time the allocated size, after something
		     was received, the actual size of the received data. */
	struct ib_sge sge;
};

struct drbd_rdma_tx_desc {
	enum {
		SEND_PAGE,
		SEND_MSG,
	} type;
	union {
		struct page *page;
		struct completion *completion;
	};
	struct ib_sge sge;
	struct list_head tx_entry;
};

struct dtr_cm {
	struct rdma_cm_id *id;
	enum drbd_rdma_state state;
	wait_queue_head_t state_wq;
};

struct drbd_rdma_stream {
	struct dtr_cm cm;

	struct ib_cq *recv_cq;
	struct ib_cq *send_cq;
	struct ib_pd *pd;
	struct ib_qp *qp;

	struct ib_mr *dma_mr;

	wait_queue_head_t recv_wq;

	/* number of currently available descs */
	atomic_t tx_descs_posted;
	int rx_descs_posted;
	int rx_descs_allocated;
	int rx_descs_want_posted;

	/* for recv() to keep track of the current rx_desc:
	 * - whenever the bytes_left of the current rx_desc == 0, we know that all data
	 *   is consumed, and get a new rx_desc from the completion queue, and set
	 *   current rx_desc accodingly.
	 */
	struct {
		struct drbd_rdma_rx_desc *desc;
		void *pos;
		int bytes_left;
	} current_rx;
	int rx_allocation_size;

	unsigned long recv_timeout;
	char name[8]; /* "control" or "data" */
};

struct drbd_rdma_transport {
	struct drbd_transport transport;
	struct drbd_rdma_stream *stream[2];
};

struct dtr_listener {
	struct drbd_listener listener;

	struct dtr_cm cm;
};

struct dtr_waiter {
	struct drbd_waiter waiter;

	struct rdma_cm_id *child_id;
};

static struct drbd_transport *dtr_create(struct drbd_connection *connection);
static void dtr_free(struct drbd_transport *transport, enum drbd_tr_free_op);
static int dtr_connect(struct drbd_transport *transport);
static int dtr_recv(struct drbd_transport *transport, enum drbd_stream stream, void **buf, size_t size, int flags);
static void dtr_stats(struct drbd_transport *transport, struct drbd_transport_stats *stats);
static void dtr_set_rcvtimeo(struct drbd_transport *transport, enum drbd_stream stream, long timeout);
static long dtr_get_rcvtimeo(struct drbd_transport *transport, enum drbd_stream stream);
static int dtr_send_page(struct drbd_transport *transport, enum drbd_stream stream, struct page *page,
		int offset, size_t size, unsigned msg_flags);
static int dtr_recv_pages(struct drbd_peer_device *peer_device, struct page **page, size_t size);
static bool dtr_stream_ok(struct drbd_transport *transport, enum drbd_stream stream);
static bool dtr_hint(struct drbd_transport *transport, enum drbd_stream stream, enum drbd_tr_hints hint);

static int dtr_post_tx_desc(struct drbd_rdma_stream *rdma_stream, struct drbd_rdma_tx_desc *tx_desc);
static int dtr_drain_rx_cq(struct drbd_rdma_stream *, struct drbd_rdma_rx_desc **, int);
static void dtr_recycle_rx_desc(struct drbd_rdma_stream *rdma_stream,
			       struct drbd_rdma_rx_desc *rx_desc);
static void dtr_refill_rx_desc(struct drbd_rdma_transport *rdma_transport,
			       enum drbd_stream stream);
static void dtr_free_rx_desc(struct drbd_rdma_stream *rdma_stream, struct drbd_rdma_rx_desc *rx_desc);
static void dtr_disconnect_stream(struct drbd_rdma_stream *rdma_stream);
static void dtr_free_stream(struct drbd_rdma_stream *rdma_stream);
static bool dtr_connection_established(struct drbd_connection *, struct drbd_rdma_stream **, struct drbd_rdma_stream **);
static bool dtr_stream_ok_or_free(struct drbd_rdma_stream **rdma_stream);


static struct drbd_transport_class rdma_transport_class = {
	.name = "rdma",
	.create = dtr_create,
	.list = LIST_HEAD_INIT(rdma_transport_class.list),
};

static struct drbd_transport_ops dtr_ops = {
	.free = dtr_free,
	.connect = dtr_connect,
	.recv = dtr_recv,
	.stats = dtr_stats,
	.set_rcvtimeo = dtr_set_rcvtimeo,
	.get_rcvtimeo = dtr_get_rcvtimeo,
	.send_page = dtr_send_page,
	.recv_pages = dtr_recv_pages,
	.stream_ok = dtr_stream_ok,
	.hint = dtr_hint,
};


static struct drbd_transport *dtr_create(struct drbd_connection *connection)
{
	struct drbd_rdma_transport *rdma_transport;

	if (!try_module_get(THIS_MODULE))
		return NULL;

	rdma_transport = kzalloc(sizeof(struct drbd_rdma_transport), GFP_KERNEL);
	if (!rdma_transport) {
		module_put(THIS_MODULE);
		return NULL;
	}

	rdma_transport->transport.ops = &dtr_ops;
	rdma_transport->transport.connection = connection;

	return &rdma_transport->transport;
}

static void dtr_free(struct drbd_transport *transport, enum drbd_tr_free_op free_op)
{
	struct drbd_rdma_transport *rdma_transport =
		container_of(transport, struct drbd_rdma_transport, transport);
	enum drbd_stream i;

	for (i = DATA_STREAM; i <= CONTROL_STREAM; i++)
		dtr_disconnect_stream(rdma_transport->stream[i]);

	if (free_op == DESTROY_TRANSPORT) {
		for (i = DATA_STREAM; i <= CONTROL_STREAM; i++)
			dtr_free_stream(rdma_transport->stream[i]);
		kfree(rdma_transport);
		module_put(THIS_MODULE);
	}
}


static int dtr_send(struct drbd_rdma_stream *rdma_stream, void *buf, size_t size)
{
	struct ib_device *device;
	struct drbd_rdma_tx_desc tx_desc;
	struct completion completion;

	printk("send in %s stream with data[0]:%x\n", rdma_stream->name, ((char*)buf)[0]);

	device = rdma_stream->cm.id->device;
	tx_desc.type = SEND_MSG;
	tx_desc.completion = &completion;
	tx_desc.sge.addr = ib_dma_map_single(device, buf, size, DMA_TO_DEVICE);
	tx_desc.sge.lkey = rdma_stream->dma_mr->lkey;
	tx_desc.sge.length = size;

	init_completion(&completion);
	dtr_post_tx_desc(rdma_stream, &tx_desc);
	wait_for_completion(&completion);

	return size;
}


static int dtr_recv_pages(struct drbd_peer_device *peer_device, struct page **pages, size_t size)
{
	/* TODO: Here we pass back pages that we allocated using alloc_page(GFP_KERNEL) while
	   DRBD thinks they came from drbd_alloc_pages(). Needs to be fixed by making
	   drbd_alloc_pages usable for transports. */

	struct drbd_rdma_transport *rdma_transport =
		container_of(peer_device->connection->transport, struct drbd_rdma_transport, transport);
	struct drbd_rdma_stream *rdma_stream = rdma_transport->stream[DATA_STREAM];
	struct page *page, *all_pages = NULL;
	int t, i = 0;

	printk("RDMA: in recv_pages, size: %zu\n", size);
	D_ASSERT(peer_device, rdma_stream->current_rx.bytes_left == 0);
	dtr_recycle_rx_desc(rdma_stream, rdma_stream->current_rx.desc);

	while (size) {
		struct drbd_rdma_rx_desc *rx_desc = NULL;

		t = wait_event_interruptible_timeout(rdma_stream->recv_wq,
					dtr_drain_rx_cq(rdma_stream, &rx_desc, 1),
					rdma_stream->recv_timeout);

		if (t <= 0) {
			if (t == 0)
				printk("RDMA: recv() on data timed out, ret: EAGAIN\n");
			else
				printk("RDMA: recv() on data timed out, ret: EINTR\n");

			atomic_add(i, &peer_device->device->pp_in_use);
			drbd_free_pages(peer_device->device, all_pages, 0);
			return t == 0 ? -EAGAIN : -EINTR;
		}

		page = rx_desc->page;
		rx_desc->page = NULL;
		size -= rx_desc->size;
		dtr_free_rx_desc(rdma_stream, rx_desc);

		set_page_private(page, (unsigned long)all_pages);
		all_pages = page;
		i++;
	}

	dtr_refill_rx_desc(rdma_transport, DATA_STREAM);
	printk("rcvd %d pages\n", i);
	atomic_add(i, &peer_device->device->pp_in_use);
	*pages = all_pages;
	return 0;
}

static int _dtr_recv(struct drbd_rdma_stream *rdma_stream, void **buf, size_t size, int flags)
{
	struct drbd_rdma_rx_desc *rx_desc = NULL;
	void *buffer;

	if (flags & GROW_BUFFER) { /* grow is untested, do not trust this code */
		printk("RDMA: recv GROW_BUFFER\n");
		/* D_ASSERT(transport->connection, *buf == tcp_transport->rbuf[stream].base); */
		buffer = rdma_stream->current_rx.pos;
		rdma_stream->current_rx.pos += size;
		/* D_ASSERT(transport->connection, (buffer - *buf) + size <= PAGE_SIZE); */
		*buf = buffer;
		/* old_rx[stream] = NULL; */
	} else if (rdma_stream->current_rx.bytes_left == 0) { /* get a completely new entry, old now unused, free it */
			int t;
			/* RCK: later we will have a better strategy to decide how/if we recycle rx_desc, for now free the old one... */
			printk("RDMA: free %p and recv completely new on %s\n", rdma_stream->current_rx.desc, rdma_stream->name);
			dtr_recycle_rx_desc(rdma_stream, rdma_stream->current_rx.desc);
			printk("waiting for %lu\n", rdma_stream->recv_timeout);
			t = wait_event_interruptible_timeout(rdma_stream->recv_wq,
						dtr_drain_rx_cq(rdma_stream, &rx_desc, 1),
						rdma_stream->recv_timeout);

			if (t <= 0)
			{
				if (t==0)
					printk("RDMA: recv() on %s timed out, ret: EAGAIN\n", rdma_stream->name);
				else
					printk("RDMA: recv() on %s timed out, ret: EINTR\n", rdma_stream->name);
				return t == 0 ? -EAGAIN : -EINTR;
			}

			printk("got a new page with size: %d\n", rx_desc->size);
			buffer = rx_desc->data;
			rdma_stream->current_rx.desc = rx_desc;
			rdma_stream->current_rx.pos = buffer + size;
			rdma_stream->current_rx.bytes_left = rx_desc->size - size;
			if (rdma_stream->current_rx.bytes_left < 0)
				printk("new, requesting more (%zu) than available (%d)\n", size, rx_desc->size);

			if (flags & CALLER_BUFFER) {
				printk("doing a memcpy on first\n");
				memcpy(*buf, buffer, size);
			} else
				*buf = buffer;

			printk("RDMA: recv completely new fine, returning size on %s\n", rdma_stream->name);
			/* RCK: of course we need a better strategy, but for now, just add a new rx_desc if we consumed one... */
			printk("rx_count(%s): %d\n", rdma_stream->name, rdma_stream->rx_descs_posted);

			return size;
		} else { /* return next part */
			printk("RDMA: recv next part on %s\n", rdma_stream->name);
			buffer = rdma_stream->current_rx.pos;
			rdma_stream->current_rx.pos += size;

			if (rdma_stream->current_rx.bytes_left <= size) { /* < could be a problem, right? or does that happen? */
				rdma_stream->current_rx.bytes_left = 0; /* 0 left == get new entry */
				printk("marking page as consumed\n");
			} else {
				rdma_stream->current_rx.bytes_left -= size;
				printk("old_rx left: %d\n", rdma_stream->current_rx.bytes_left);
			}

			if (flags & CALLER_BUFFER) {
				printk("doing a memcpy on next\n");
				memcpy(*buf, buffer, size);
			} else
				*buf = buffer;

			printk("RDMA: recv next part fine, returning size on %s\n", rdma_stream->name);
			return size;
		}

	return 0;
}

static int dtr_recv(struct drbd_transport *transport, enum drbd_stream stream, void **buf, size_t size, int flags)
{
	struct drbd_rdma_transport *rdma_transport =
		container_of(transport, struct drbd_rdma_transport, transport);

	struct drbd_rdma_stream *rdma_stream = rdma_transport->stream[stream];
	int err;

	err = _dtr_recv(rdma_stream, buf, size, flags);

	dtr_refill_rx_desc(rdma_transport, stream);
	return err;
}

static void dtr_stats(struct drbd_transport* transport, struct drbd_transport_stats *stats)
{
	struct drbd_rdma_transport *rdma_transport =
		container_of(transport, struct drbd_rdma_transport, transport);

	/* RCK: first two for debugfs, for now do not care */
	stats->unread_received = 0;
	stats->unacked_send = 0;

	/* RCK: these are used by the sender, guess we should them get right */
	stats->send_buffer_size = RDMA_MAX_TX;
	stats->send_buffer_used = atomic_read(&(rdma_transport->stream[DATA_STREAM]->tx_descs_posted));
}

static int dtr_cma_event_handler(struct rdma_cm_id *cm_id, struct rdma_cm_event *event)
{
	int err;
	/* context comes from rdma_create_id() */
	struct dtr_cm *cm_context = cm_id->context;
	struct dtr_listener *listener;
	struct drbd_waiter *waiter;
	struct dtr_waiter *dtr_waiter;

	switch (event->event) {
	case RDMA_CM_EVENT_ADDR_RESOLVED:
		printk("RDMA(cma event): addr resolved\n");
		cm_context->state = ADDR_RESOLVED;
		err = rdma_resolve_route(cm_id, 2000);
		if (err) {
			printk("RDMA: rdma_resolve_route error %d\n", err);
			wake_up_interruptible(&cm_context->state_wq);
		}
		else {
			printk("RDMA: rdma_resolve_route OK\n");
		}
		break;

	case RDMA_CM_EVENT_ROUTE_RESOLVED:
		printk("RDMA(cma event): route resolved\n");
		cm_context->state = ROUTE_RESOLVED;
		wake_up_interruptible(&cm_context->state_wq);
		break;

	case RDMA_CM_EVENT_CONNECT_REQUEST:
		printk("RDMA(cma event): connect request\n");
		/* for listener */
		cm_context->state = CONNECT_REQUEST;

		listener = container_of(cm_context, struct dtr_listener, cm);

		spin_lock(&listener->listener.resource->listeners_lock);
		listener->listener.pending_accepts++;
		waiter = list_entry(listener->listener.waiters.next, struct drbd_waiter, list);
		dtr_waiter = container_of(waiter, struct dtr_waiter, waiter);
		dtr_waiter->child_id = cm_id;
		wake_up(&waiter->wait);
		spin_unlock(&listener->listener.resource->listeners_lock);

		printk("RDMA: child cma %p\n", cm_id);
		break;

	case RDMA_CM_EVENT_ESTABLISHED:
		printk("RDMA(cma event): established\n");
		cm_context->state = CONNECTED;
		wake_up_interruptible(&cm_context->state_wq);
		break;

	case RDMA_CM_EVENT_ADDR_ERROR:
		printk("RDMA(cma event, err): ADDR_ERROR\n");
	case RDMA_CM_EVENT_ROUTE_ERROR:
		printk("RDMA(cma event, err): ADDR_ROUTE_ERROR\n");
	case RDMA_CM_EVENT_CONNECT_ERROR:
		printk("RDMA(cma event, err): ADDR_CONNECT_ERROR\n");
	case RDMA_CM_EVENT_UNREACHABLE:
		printk("RDMA(cma event, err): ADDR_UNREACHABLE\n");
	case RDMA_CM_EVENT_REJECTED:
		printk("RDMA(cma event, err): ADDR_REJECTED\n");
		printk("RDMA(cma event: bad thingy, fall-through, only first valid) %d, error %d\n", event->event, event->status);
		cm_context->state = ERROR;
		wake_up_interruptible(&cm_context->state_wq);
		break;

	case RDMA_CM_EVENT_DISCONNECTED:
		printk("RDMA(cma event) disconnect event\n");
		cm_context->state = DISCONNECTED;
		wake_up_interruptible(&cm_context->state_wq);
		break;

	case RDMA_CM_EVENT_DEVICE_REMOVAL:
		printk("RDMA(cma event): detected device removal!\n");
		break;

	default:
		printk("RDMA(cma event): oof bad type!\n");
		wake_up_interruptible(&cm_context->state_wq);
		break;
	}
	return 0;
}

static int dtr_create_cm_id(struct dtr_cm *cm_context)
{
	cm_context->state = IDLE;
	init_waitqueue_head(&cm_context->state_wq);
	cm_context->id = NULL;

	cm_context->id = rdma_create_id(dtr_cma_event_handler,
					cm_context, RDMA_PS_TCP, IB_QPT_RC);

	return cm_context->id ? 0 : -ENOMEM;
}

/* receive max nr_elements (currently should always be used with "1"
 * if -1: receive all
 * >= 0 : nr_elements
 * number of elements in cq is too small to underflow nr_elements */
static int dtr_drain_rx_cq(struct drbd_rdma_stream *rdma_stream, struct drbd_rdma_rx_desc **rx_desc, int nr_elements)
{
	struct ib_cq *cq = rdma_stream->recv_cq;
	struct ib_wc wc;
	int completed_tx = 0;
	int size;

	while (nr_elements-- && (ib_poll_cq(cq, 1, &wc) == 1)) {
		*rx_desc = (struct drbd_rdma_rx_desc *) (unsigned long) wc.wr_id;
		WARN_ON(rx_desc == NULL);

		if(wc.status == IB_WC_SUCCESS) {
			printk("RDMA: IB_WC_SUCCESS\n");
			if (wc.opcode == IB_WC_SEND)
				printk("RDMA: IB_WC_SEND\n");
			if (wc.opcode == IB_WC_RECV) {
				printk("RDMA: IB_WC_RECV\n");
				size = wc.byte_len;
				printk("RDMA: size: %d\n", size);
				ib_dma_sync_single_for_cpu(rdma_stream->cm.id->device, (*rx_desc)->dma_addr,
						RDMA_PAGE_SIZE, DMA_FROM_DEVICE);
				(*rx_desc)->size = size;
				printk("in drain (%s): %p, data[0]:%x\n", rdma_stream->name, rx_desc, (*rx_desc)->data[0]);
			}
			else if (wc.opcode == IB_WC_RDMA_WRITE)
				printk("RDMA: IB_WC_RDMA_WRITE\n");
			else if (wc.opcode == IB_WC_RDMA_READ)
				printk("RDMA: IB_WC_RDMA_READ\n");
			else
				printk("RDMA: WC SUCCESS, but strange opcode...\n");

			completed_tx++;
		}
		else
			printk("RDMA: IB_WC NOT SUCCESS\n");
	}

	/* ib_req_notify_cq(cq, IB_CQ_NEXT_COMP); */

	return completed_tx;
}

static void dtr_rx_cq_event_handler(struct ib_cq *cq, void *ctx)
{
	struct drbd_rdma_stream *rdma_stream = ctx;
	int ret;

	printk("RDMA (%s): got rx cq event. state %d\n", rdma_stream->name, rdma_stream->cm.state);
	rdma_stream->rx_descs_posted--;

	wake_up_interruptible(&rdma_stream->recv_wq);
	ret = ib_req_notify_cq(cq, IB_CQ_NEXT_COMP);
	if (ret)
		printk("ib_req_notify_cq failed\n");
	else
		printk("ib_req_notify_cq success\n");

}

static void dtr_tx_cq_event_handler(struct ib_cq *cq, void *ctx)
{
	struct drbd_rdma_stream *rdma_stream = ctx;
	struct ib_device *device = rdma_stream->cm.id->device;
	struct drbd_rdma_tx_desc *tx_desc;
	struct ib_wc wc;
	int ret;

	printk("RDMA (%s): got tx cq event. state %d\n", rdma_stream->name, rdma_stream->cm.state);

	ret = ib_req_notify_cq(cq, IB_CQ_NEXT_COMP);
	if (ret)
		printk("ib_req_notify_cq failed\n");
	else
		printk("ib_req_notify_cq success\n");

	/* Alternatively put them onto a list here, and do the processing (freeing)
	   at a later point in time. Probably resource freeing is cheap enough to do
	   it directly here. */
	while ((ret = ib_poll_cq(cq, 1, &wc)) == 1) {
		atomic_dec(&rdma_stream->tx_descs_posted);

		if (wc.status != IB_WC_SUCCESS) {
			printk("wc.status != IB_WC_SUCCESS %d\n", wc.status);
			goto disconnect;
		}

		if (wc.opcode != IB_WC_SEND) {
			printk("wc.opcode != IB_WC_SEND %d\n", wc.opcode);
			goto disconnect;
		}

		tx_desc = (struct drbd_rdma_tx_desc *) (unsigned long) wc.wr_id;

		switch (tx_desc->type) {
		case SEND_PAGE:
			printk("put_page(%p), kfree(%p)\n", tx_desc->page, tx_desc);
			ib_dma_unmap_page(device, tx_desc->sge.addr, tx_desc->sge.length, DMA_TO_DEVICE);
			put_page(tx_desc->page);
			kfree(tx_desc);
			break;
		case SEND_MSG:
			printk("complete(%p)\n", tx_desc->completion);
			ib_dma_unmap_single(device, tx_desc->sge.addr, tx_desc->sge.length, DMA_TO_DEVICE);
			complete(tx_desc->completion);
			break;
		}
	}

	if (ret != -1)
		printk("ib_poll_cq() returned %d\n", ret);

disconnect:
	/* TODO */;
}

static int dtr_create_qp(struct drbd_rdma_stream *rdma_stream)
{
	struct ib_qp_init_attr init_attr;
	int err;

	memset(&init_attr, 0, sizeof(init_attr));
	init_attr.cap.max_send_wr = RDMA_MAX_TX;
	init_attr.cap.max_recv_wr = RDMA_MAX_RX;
	init_attr.cap.max_recv_sge = 1;
	init_attr.cap.max_send_sge = 1;
	init_attr.qp_type = IB_QPT_RC;
	init_attr.send_cq = rdma_stream->send_cq;
	init_attr.recv_cq = rdma_stream->recv_cq;
	init_attr.sq_sig_type = IB_SIGNAL_REQ_WR;

	err = rdma_create_qp(rdma_stream->cm.id, rdma_stream->pd, &init_attr);
	if (err) {
		printk("RDMA: rdma_create_qp failed: %d\n", err);
		return err;
	}

	rdma_stream->qp = rdma_stream->cm.id->qp;
	printk("RDMA: created qp %p\n", rdma_stream->qp);
	return 0;
}

static int dtr_post_rx_desc(struct drbd_rdma_stream *rdma_stream,
		struct drbd_rdma_rx_desc *rx_desc)
{
	struct ib_recv_wr recv_wr, *recv_wr_failed;
	int err;

	recv_wr.next = NULL;
	recv_wr.wr_id = (unsigned long)rx_desc;
	recv_wr.sg_list = &rx_desc->sge;
	recv_wr.num_sge = 1;

	ib_dma_sync_single_for_device(rdma_stream->cm.id->device,
			rx_desc->dma_addr, RDMA_PAGE_SIZE, DMA_FROM_DEVICE);

	rdma_stream->rx_descs_posted++;
	err = ib_post_recv(rdma_stream->qp, &recv_wr, &recv_wr_failed);
	if (err) {
		printk("RDMA: ib_post_recv error %d\n", err);
		rdma_stream->rx_descs_posted--;
		return err;
	}

	return 0;
}

static void dtr_free_rx_desc(struct drbd_rdma_stream *rdma_stream, struct drbd_rdma_rx_desc *rx_desc)
{
	if (!rx_desc)
		return; /* Allow call with NULL */

	rdma_stream->rx_descs_allocated--;
	if (rx_desc->page)
		put_page(rx_desc->page);
	kfree(rx_desc);
}

/* RCK: for the first hack it is ok, but if we change the size of data in rx_desc, we
 * have to include "enum drbd_stream" as param */
static int dtr_create_some_rx_desc(struct drbd_rdma_stream *rdma_stream)
{
	struct drbd_rdma_rx_desc *rx_desc;
	struct ib_device *device = rdma_stream->cm.id->device;
	struct page *page;
	void *pos;
	int err, size, alloc_size = rdma_stream->rx_allocation_size;

	/* Should use drbd_alloc_pages() here. But that needs a peer_device.
	   Need to refactor that to be based on connections.
	page = drbd_alloc_pages(peer_device, 1, GFP_TRY);
	drbd_free_pages(peer_device->device, page, 0);
	*/

	page = alloc_page(GFP_NOIO);
	if (!page)
		return -ENOMEM;

	pos = page_address(page);
	size = PAGE_SIZE;

	while (size) {
		rx_desc = kzalloc(sizeof(*rx_desc), GFP_NOIO);
		if (!rx_desc) {
			put_page(page);
			return -ENOMEM;
		}
		rdma_stream->rx_descs_allocated++;

		printk("alloced rx_desc %p\n", rx_desc);

		get_page(page);
		rx_desc->page = page;
		rx_desc->data = pos;
		rx_desc->size = alloc_size;
		rx_desc->dma_addr = ib_dma_map_single(device, pos, alloc_size,
						      DMA_FROM_DEVICE);
		rx_desc->sge.lkey = rdma_stream->dma_mr->lkey;
		rx_desc->sge.addr = rx_desc->dma_addr;
		rx_desc->sge.length = alloc_size;

		pos += alloc_size;
		size -= alloc_size;

		err = dtr_post_rx_desc(rdma_stream, rx_desc);
		if (err) {
			dtr_free_rx_desc(rdma_stream, rx_desc);
			break;
		}
	}

	put_page(page);

	return err;
}

static void dtr_refill_rx_desc(struct drbd_rdma_transport *rdma_transport,
			       enum drbd_stream stream)
{
	struct drbd_connection *connection = rdma_transport->transport.connection;
	int rcvbuf_size = RDMA_DEF_RECV_SIZE; /* Hardcoded default of 512 KiByte */
	struct drbd_rdma_stream *rdma_stream = rdma_transport->stream[stream];
	int descs_posted, descs_max;
	struct net_conf *nc;

	rcu_read_lock();
	nc = rcu_dereference(connection->net_conf);
	if (nc) {
		if (nc->rcvbuf_size)
			rcvbuf_size = nc->rcvbuf_size;
	}
	rcu_read_unlock();

	descs_max = rcvbuf_size / DRBD_SOCKET_BUFFER_SIZE;
	/* The above statement is obvious for the DATA_STREAM. We use the same
	   number of descriptors for the CONTROL_STREAM as well, though that
	   covers only a 64th fraction of the size in bytes available. I.e.
	   by default two pages. */

	descs_posted = descs_max / 2;
	rdma_stream->rx_descs_want_posted = descs_posted;

	while (rdma_stream->rx_descs_posted < descs_posted &&
	       rdma_stream->rx_descs_allocated < descs_max)
		dtr_create_some_rx_desc(rdma_stream);
}

static void dtr_repost_rx_desc(struct drbd_rdma_stream *rdma_stream,
			       struct drbd_rdma_rx_desc *rx_desc)
{
	struct ib_device *device = rdma_stream->cm.id->device;
	int err;

	rx_desc->size = rdma_stream->rx_allocation_size;
	rx_desc->dma_addr = ib_dma_map_single(device, rx_desc->data,
					      rx_desc->size,
					      DMA_FROM_DEVICE);
	rx_desc->sge.lkey = rdma_stream->dma_mr->lkey;
	rx_desc->sge.addr = rx_desc->dma_addr;
	rx_desc->sge.length = rx_desc->size;

	err = dtr_post_rx_desc(rdma_stream, rx_desc);
	if (err)
		dtr_free_rx_desc(rdma_stream, rx_desc);
}

static void dtr_recycle_rx_desc(struct drbd_rdma_stream *rdma_stream,
			       struct drbd_rdma_rx_desc *rx_desc)
{
	int want_posted = rdma_stream->rx_descs_want_posted + 8; /*hysteresis*/

	if (!rx_desc)
		return;

	if (rdma_stream->rx_descs_posted > want_posted)
		dtr_free_rx_desc(rdma_stream, rx_desc);
	else
		dtr_repost_rx_desc(rdma_stream, rx_desc);
}

/* RCK: we use stream to differentiate between rdma send and write:
 * control stream: rdma send
 * data stream: rdma write
 * data should be/has to be an rdma write
 * CURRENTLY only SEND, and and the write is up to discussion, see list at the
 * beginning of file */
static int dtr_post_tx_desc(struct drbd_rdma_stream *rdma_stream, struct drbd_rdma_tx_desc *tx_desc)
{
	struct ib_device *device = rdma_stream->cm.id->device;
	struct ib_send_wr send_wr, *send_wr_failed;
	int err;
	printk("in dtr_post_tx_desc\n");

	send_wr.next = NULL;
	send_wr.wr_id = (unsigned long)tx_desc;
	send_wr.sg_list = &tx_desc->sge;
	send_wr.num_sge = 1;
	send_wr.opcode = IB_WR_SEND;
	send_wr.send_flags = IB_SEND_SIGNALED;

	ib_dma_sync_single_for_device(device, tx_desc->sge.addr,
			tx_desc->sge.length, DMA_TO_DEVICE);
	atomic_inc(&rdma_stream->tx_descs_posted);

	err = ib_post_send(rdma_stream->qp, &send_wr, &send_wr_failed);
	if (err) {
		printk("RDMA: ib_post_send failed\n");
		atomic_dec(&rdma_stream->tx_descs_posted);

		return err;
	} else {
		/* printk("RDMA: ib_post_send successfull!\n"); */
		printk("Created send_wr (%p, %p): lkey=%x, addr=%llx, length=%d\n", tx_desc->page, tx_desc, tx_desc->sge.lkey, tx_desc->sge.addr, tx_desc->sge.length);
	}

	return 0;
}

/* allocate rdma specific resources for the stream */
static int dtr_alloc_rdma_resources(struct drbd_rdma_stream *rdma_stream)
{
	int err;

	rdma_stream->current_rx.desc = NULL;
	rdma_stream->current_rx.pos = NULL;
	rdma_stream->current_rx.bytes_left = 0;

	rdma_stream->recv_timeout = 1000 * HZ; /* RCK TODO: this should be the netconf value */

	strcpy(rdma_stream->name, "new");
	rdma_stream->rx_allocation_size = DRBD_SOCKET_BUFFER_SIZE; /* 4096 usually PAGE_SIZE */

	init_waitqueue_head(&rdma_stream->recv_wq);

	printk("RDMA: here with cm_id: %p\n", rdma_stream->cm.id);

	/* alloc protection domain (PD) */
	rdma_stream->pd = ib_alloc_pd(rdma_stream->cm.id->device);
	if (IS_ERR(rdma_stream->pd)) {
		printk("RDMA: ib_alloc_pd failed\n");
		err = PTR_ERR(rdma_stream->pd);
		goto pd_failed;
	}
	printk("RDMA: created pd %p\n", rdma_stream->pd);

	/* create recv completion queue (CQ) */
	rdma_stream->recv_cq = ib_create_cq(rdma_stream->cm.id->device,
		dtr_rx_cq_event_handler, NULL, rdma_stream, RDMA_MAX_RX, 0);
	if (IS_ERR(rdma_stream->recv_cq)) {
		printk("RDMA: ib_create_cq recv failed\n");
		err = PTR_ERR(rdma_stream->recv_cq);
		goto recv_cq_failed;
	}
	printk("RDMA: created recv cq %p\n", rdma_stream->recv_cq);

	/* create send completion queue (CQ) */
	rdma_stream->send_cq = ib_create_cq(rdma_stream->cm.id->device,
		dtr_tx_cq_event_handler, NULL, rdma_stream, RDMA_MAX_TX, 0);
	if (IS_ERR(rdma_stream->send_cq)) {
		printk("RDMA: ib_create_cq send failed\n");
		err = PTR_ERR(rdma_stream->send_cq);
		goto send_cq_failed;
	}
	printk("RDMA: created send cq %p\n", rdma_stream->send_cq);

	/* arm CQs */
	err = ib_req_notify_cq(rdma_stream->recv_cq, IB_CQ_NEXT_COMP);
	if (err) {
		printk("RDMA: ib_req_notify_cq recv failed\n");
		goto notify_failed;
	}

	err = ib_req_notify_cq(rdma_stream->send_cq, IB_CQ_NEXT_COMP);
	if (err) {
		printk("RDMA: ib_req_notify_cq send failed\n");
		goto notify_failed;
	}

	/* create a queue pair (QP) */
	err = dtr_create_qp(rdma_stream);
	if (err) {
		printk("RDMA: create_qp error %d\n", err);
		goto createqp_failed;
	}

	/* create RDMA memory region (MR) */
	rdma_stream->dma_mr = ib_get_dma_mr(rdma_stream->pd,
			IB_ACCESS_LOCAL_WRITE |
			IB_ACCESS_REMOTE_READ |
			IB_ACCESS_REMOTE_WRITE);
	if (IS_ERR(rdma_stream->dma_mr)) {
		printk("RDMA: ib_get_dma_mr failed\n");
		err = PTR_ERR(rdma_stream->dma_mr);
		goto dma_failed;
	}

	dtr_create_some_rx_desc(rdma_stream);

	return 0;

dma_failed:
	ib_destroy_qp(rdma_stream->qp);
	rdma_stream->qp = NULL;
createqp_failed:
notify_failed:
	ib_destroy_cq(rdma_stream->send_cq);
	rdma_stream->send_cq = NULL;
send_cq_failed:
	ib_destroy_cq(rdma_stream->recv_cq);
	rdma_stream->recv_cq = NULL;
recv_cq_failed:
	ib_dealloc_pd(rdma_stream->pd);
	rdma_stream->pd = NULL;
pd_failed:
	return err;
}


static void dtr_free_stream(struct drbd_rdma_stream *rdma_stream)
{
	if (!rdma_stream)
		return;

	dtr_disconnect_stream(rdma_stream);

	if (rdma_stream->dma_mr)
		ib_dereg_mr(rdma_stream->dma_mr);
	if (rdma_stream->qp)
		ib_destroy_qp(rdma_stream->qp);
	if (rdma_stream->send_cq)
		ib_destroy_cq(rdma_stream->send_cq);
	if (rdma_stream->recv_cq)
		ib_destroy_cq(rdma_stream->recv_cq);
	if (rdma_stream->pd)
		ib_dealloc_pd(rdma_stream->pd);
	if (rdma_stream->cm.id)
		rdma_destroy_id(rdma_stream->cm.id);

	kfree(rdma_stream);
}

static int dtr_send_first_packet(struct drbd_rdma_stream *rdma_stream, enum drbd_packet cmd)
{
	struct p_header80 h;
	int err;

	if (!rdma_stream)
		return -EIO;

	h.magic = cpu_to_be32(DRBD_MAGIC);
	h.command = cpu_to_be16(cmd);
	h.length = 0;

	err = dtr_send(rdma_stream, &h, sizeof(h));

	return err;
}

static int dtr_receive_first_packet(struct drbd_connection *connection, struct drbd_rdma_stream *rdma_stream)
{
	struct p_header80 *h;
	const unsigned int header_size = sizeof(*h);
	struct net_conf *nc;
	int err;

	rcu_read_lock();
	nc = rcu_dereference(connection->net_conf);
	if (!nc) {
		rcu_read_unlock();
		return -EIO;
	}
	rdma_stream->recv_timeout = nc->ping_timeo * 4 * HZ / 10;
	rcu_read_unlock();

	err = _dtr_recv(rdma_stream, (void **)&h, sizeof(*h), 0);
	if (err != header_size) {
		if (err >= 0)
			err = -EIO;
		return err;
	}
	dtr_create_some_rx_desc(rdma_stream);

	if (h->magic != cpu_to_be32(DRBD_MAGIC)) {
		drbd_err(connection, "Wrong magic value 0x%08x in receive_first_packet\n",
			 be32_to_cpu(h->magic));
		return -EINVAL;
	}
	return be16_to_cpu(h->command);
}


static int dtr_try_connect(struct drbd_connection *connection, struct drbd_rdma_stream **ret_rdma_stream)
{
	struct drbd_rdma_stream *rdma_stream = NULL;
	struct rdma_conn_param conn_param;
	int err = -ENOMEM;

	rdma_stream = kzalloc(sizeof(*rdma_stream), GFP_KERNEL);
	if (!rdma_stream)
		goto out;

	err = dtr_create_cm_id(&rdma_stream->cm);
	if (err) {
		printk("rdma_create_id() failed\n");
		goto out;
	}

	err = rdma_resolve_addr(rdma_stream->cm.id, NULL, (struct sockaddr *)&connection->peer_addr, 2000);
	if (err) {
		printk("RDMA: rdma_resolve_addr error %d\n", err);
		goto out;
	}

	wait_event_interruptible(rdma_stream->cm.state_wq,
				 rdma_stream->cm.state >= ROUTE_RESOLVED);

	if (rdma_stream->cm.state != ROUTE_RESOLVED) {
		printk("RDMA addr/route resolution error. state %d\n", rdma_stream->cm.state);
		goto out;
	}

	err = dtr_alloc_rdma_resources(rdma_stream);
	if (err) {
		printk("RDMA: failed allocating resources %d\n", err);
		goto out;
	}

	/* Connect peer */
	memset(&conn_param, 0, sizeof conn_param);
	conn_param.responder_resources = 1;
	conn_param.initiator_depth = 1;
	conn_param.retry_count = 10;

	err = rdma_connect(rdma_stream->cm.id, &conn_param);
	if (err) {
		printk("RDMA: rdma_connect error %d\n", err);
		goto out;
	}

	wait_event_interruptible(rdma_stream->cm.state_wq,
			rdma_stream->cm.state >= CONNECTED);
	if (rdma_stream->cm.state == ERROR) {
		printk("RDMA: failed connecting. state %d\n", rdma_stream->cm.state);
		goto out;
	}
	printk("RDMA: rdma_connect successful\n");


	*ret_rdma_stream = rdma_stream;
	return 0;
out:
	dtr_free_stream(rdma_stream);
	return err;
}

static void dtr_destroy_listener(struct drbd_listener *generic_listener)
{
	struct dtr_listener *listener =
		container_of(generic_listener, struct dtr_listener, listener);

	rdma_destroy_id(listener->cm.id);
	kfree(listener);
}

static int dtr_create_listener(struct drbd_connection *connection, struct drbd_listener **ret_listener)
{
	struct dtr_listener *listener = NULL;
	int err = -ENOMEM;

	listener = kzalloc(sizeof(*listener), GFP_KERNEL);
	if (!listener)
		goto out;

	err = dtr_create_cm_id(&listener->cm);
	if (err) {
		printk("rdma_create_id() failed\n");
		goto out;
	}

	err = rdma_bind_addr(listener->cm.id, (struct sockaddr *) &connection->my_addr);
	if (err) {
		printk("RDMA: rdma_bind_addr error %d\n", err);
		goto out;
	}

	err = rdma_listen(listener->cm.id, 3);
	if (err) {
		printk("RDMA: rdma_listen error %d\n", err);
		goto out;
	}

	listener->listener.listen_addr = connection->my_addr;
	listener->listener.destroy = dtr_destroy_listener;

	*ret_listener = &listener->listener;
	return 0;
out:
	if (listener && listener->cm.id)
		rdma_destroy_id(listener->cm.id);
	kfree(listener);
	return err;
}

static bool dtr_wait_connect_cond(struct dtr_waiter *waiter)
{
	struct drbd_connection *connection = waiter->waiter.connection;
	struct drbd_resource *resource = connection->resource;
	bool rv;

	spin_lock_bh(&resource->listeners_lock);
	rv = waiter->waiter.listener->pending_accepts > 0 || waiter->child_id != NULL;
	spin_unlock_bh(&resource->listeners_lock);

	return rv;
}

static int dtr_wait_for_connect(struct dtr_waiter *waiter, struct drbd_rdma_stream **ret_rdma_stream)
{
	struct drbd_connection *connection = waiter->waiter.connection;
	struct drbd_resource *resource = connection->resource;
	struct drbd_rdma_stream *rdma_stream = NULL;
	int timeo, connect_int, err = 0;
	struct net_conf *nc;
	struct dtr_listener *listener =
		container_of(waiter->waiter.listener, struct dtr_listener, listener);
	struct rdma_conn_param conn_param;

	rcu_read_lock();
	nc = rcu_dereference(connection->net_conf);
	if (!nc) {
		rcu_read_unlock();
		return -EINVAL;
	}
	connect_int = nc->connect_int;
	rcu_read_unlock();

	timeo = connect_int * HZ;
	timeo += (prandom_u32() & 1) ? timeo / 7 : -timeo / 7; /* 28.5% random jitter */

	timeo = wait_event_interruptible_timeout(waiter->waiter.wait, dtr_wait_connect_cond(waiter), timeo);
	if (timeo <= 0)
		return -EAGAIN;

	spin_lock_bh(&resource->listeners_lock);
	if (listener->listener.pending_accepts > 0) {
		listener->listener.pending_accepts--;
		spin_unlock_bh(&resource->listeners_lock);

		rdma_stream = kzalloc(sizeof(*rdma_stream), GFP_KERNEL);
		if (!rdma_stream)
			return -ENOMEM;

		rdma_stream->cm.state = IDLE;
		init_waitqueue_head(&rdma_stream->cm.state_wq);
		rdma_stream->cm.id = waiter->child_id;

		printk("before calling dtr_alloc_rdma_resources()\n");
		err = dtr_alloc_rdma_resources(rdma_stream);
		if (err) {
			printk("RDMA failed allocating resources %d\n", err);
			goto err;
		}

		memset(&conn_param, 0, sizeof conn_param);
		conn_param.responder_resources = 1;
		conn_param.initiator_depth = 1;

		err = rdma_accept(rdma_stream->cm.id, &conn_param);
		if (err) {
			printk("RDMA: rdma_accept error %d\n", err);
			goto err;
		}

		printk("RMDA: connection accepted\n");

		/*
		s_estab->ops->getname(s_estab, (struct sockaddr *)&peer_addr, &peer_addr_len, 2);
		TODO: Handle the case that we might have multiple connections!!!
		i.e. passing on the rdma_stream to an other waiter...

		drbd_find_waiter_by_addr(waiter->waiter.listener, &peer_addr);

		... */
	}
	spin_unlock_bh(&resource->listeners_lock);
	*ret_rdma_stream = rdma_stream;
	return 0;

err:
	dtr_free_stream(rdma_stream);
	return err;
}


/* RCK: this way of connect requires IBoIP, but I guess that is an assumption we can make
 * If this beast will ever work, we can think about all the other ways/possible fallbacks */
static int dtr_connect(struct drbd_transport *transport)
{
	struct drbd_rdma_transport *rdma_transport =
		container_of(transport, struct drbd_rdma_transport, transport);

	struct drbd_rdma_stream *data_stream = NULL, *control_stream = NULL;
	struct net_conf *nc;
	struct drbd_connection *connection;
	struct dtr_waiter waiter;
	int timeout, err;
	bool ok;

	connection = transport->connection;

	/* Assume that the peer only understands protocol 80 until we know better.  */
	connection->agreed_pro_version = 80;

	waiter.waiter.connection = connection;
	waiter.child_id = NULL;

	err = drbd_get_listener(&waiter.waiter, dtr_create_listener);
	if (err)
		return err;

	do {
		struct drbd_rdma_stream *s = NULL;

		err = dtr_try_connect(connection, &s);
		if (err < 0 && err != -EAGAIN)
			goto out;

		if (s) {
			if (!data_stream) {
				data_stream = s;
				dtr_send_first_packet(data_stream, P_INITIAL_DATA);
			} else if (!control_stream) {
				clear_bit(RESOLVE_CONFLICTS, &transport->flags);
				control_stream = s;
				dtr_send_first_packet(control_stream, P_INITIAL_META);
			} else {
				drbd_err(connection, "Logic error in conn_connect()\n");
				goto out_eagain;
			}
		}

		if (dtr_connection_established(connection, &data_stream, &control_stream))
			break;

retry:
		s = NULL;
		err = dtr_wait_for_connect(&waiter, &s);
		if (err < 0 && err != -EAGAIN)
			goto out;

		if (s) {
			int fp = dtr_receive_first_packet(connection, s);

			dtr_stream_ok_or_free(&data_stream);
			dtr_stream_ok_or_free(&control_stream);
			switch (fp) {
			case P_INITIAL_DATA:
				if (data_stream) {
					drbd_warn(connection, "initial packet S crossed\n");
					dtr_free_stream(data_stream);
					data_stream = s;
					goto randomize;
				}
				data_stream = s;
				break;
			case P_INITIAL_META:
				set_bit(RESOLVE_CONFLICTS, &transport->flags);
				if (control_stream) {
					drbd_warn(connection, "initial packet M crossed\n");
					dtr_free_stream(control_stream);
					control_stream = s;
					goto randomize;
				}
				control_stream = s;
				break;
			default:
				drbd_warn(connection, "Error receiving initial packet\n");
				dtr_free_stream(s);
randomize:
				if (prandom_u32() & 1)
					goto retry;
			}
		}

		if (connection->cstate[NOW] <= C_DISCONNECTING)
			goto out_eagain;
		if (signal_pending(current)) {
			flush_signals(current);
			smp_rmb();
			if (get_t_state(&connection->receiver) == EXITING)
				goto out_eagain;
		}

		ok = dtr_connection_established(connection, &data_stream, &control_stream);
	} while (!ok);

	drbd_put_listener(&waiter.waiter);

	strcpy(data_stream->name, "data");
	data_stream->rx_allocation_size = DRBD_SOCKET_BUFFER_SIZE; /* 4096 usually PAGE_SIZE */

	strcpy(control_stream->name, "control");
	control_stream->rx_allocation_size = DRBD_SOCKET_BUFFER_SIZE;

	rdma_transport->stream[DATA_STREAM] = data_stream;
	rdma_transport->stream[CONTROL_STREAM] = control_stream;

	rcu_read_lock();
	nc = rcu_dereference(connection->net_conf);

	timeout = nc->timeout * HZ / 10;
	rcu_read_unlock();

	data_stream->recv_timeout = timeout;
	/* control_stream->send_timeout = timeout; */

	return 0;

out_eagain:
	err = -EAGAIN;
out:
	drbd_put_listener(&waiter.waiter);
	if (data_stream)
		dtr_free_stream(data_stream);
	if (control_stream)
		dtr_free_stream(control_stream);

	return err;
}

static void dtr_set_rcvtimeo(struct drbd_transport *transport, enum drbd_stream stream, long timeout)
{
	struct drbd_rdma_transport *rdma_transport =
		container_of(transport, struct drbd_rdma_transport, transport);

	rdma_transport->stream[stream]->recv_timeout = timeout;
}

static long dtr_get_rcvtimeo(struct drbd_transport *transport, enum drbd_stream stream)
{
	struct drbd_rdma_transport *rdma_transport =
		container_of(transport, struct drbd_rdma_transport, transport);

	return rdma_transport->stream[stream]->recv_timeout;
}

static bool __dtr_stream_ok(struct drbd_rdma_stream *rdma_stream)
{
	return rdma_stream && rdma_stream->cm.id && rdma_stream->cm.state == CONNECTED;
}

static bool dtr_stream_ok(struct drbd_transport *transport, enum drbd_stream stream)
{
	struct drbd_rdma_transport *rdma_transport =
		container_of(transport, struct drbd_rdma_transport, transport);
	struct drbd_rdma_stream *rdma_stream = rdma_transport->stream[stream];

	/* RCK: Not sure if it is a valid assumption that the stream is OK as long
	 * as the CM knows about it, but for now my best guess */
	return __dtr_stream_ok(rdma_stream);
}

static bool dtr_stream_ok_or_free(struct drbd_rdma_stream **rdma_stream)
{
	if (!__dtr_stream_ok(*rdma_stream)) {
		dtr_free_stream(*rdma_stream);
		*rdma_stream = NULL;
		return false;
	}
	return true;
}

static void dtr_disconnect_stream(struct drbd_rdma_stream *rdma_stream)
{
	int err;

	if (!rdma_stream || !rdma_stream->cm.id)
		return;

	err = rdma_disconnect(rdma_stream->cm.id);
	if (err) {
		printk("rdma_disconnect() returned %d\n", err);
	}

	wait_event_interruptible(rdma_stream->cm.state_wq,
				 rdma_stream->cm.state >= DISCONNECTED);
}

static bool dtr_connection_established(struct drbd_connection *connection,
				       struct drbd_rdma_stream **stream1,
				       struct drbd_rdma_stream **stream2)
{
	struct net_conf *nc;
	int timeout;

	if (!*stream1 || !*stream2)
		return false;

	rcu_read_lock();
	nc = rcu_dereference(connection->net_conf);
	timeout = (nc->sock_check_timeo ?: nc->ping_timeo) * HZ / 10;
	rcu_read_unlock();
	schedule_timeout_interruptible(timeout);

	return __dtr_stream_ok(*stream1) && __dtr_stream_ok(*stream2);
}

static int dtr_send_page(struct drbd_transport *transport, enum drbd_stream stream,
			 struct page *page, int offset, size_t size, unsigned msg_flags)
{
	struct drbd_rdma_transport *rdma_transport =
		container_of(transport, struct drbd_rdma_transport, transport);
	struct drbd_rdma_stream *rdma_stream = rdma_transport->stream[stream];
	struct drbd_rdma_tx_desc *tx_desc;
	struct ib_device *device;
	int err;

	printk("RDMA: in send_page, size: %zu\n", size);

	tx_desc = kmalloc(sizeof(*tx_desc), GFP_NOIO);
	if(!tx_desc)
		return -ENOMEM;

	get_page(page); /* The put_page() is in dtr_tx_cq_event_handler() */
	device = rdma_stream->cm.id->device;
	tx_desc->type = SEND_PAGE;
	tx_desc->page = page;
	tx_desc->sge.addr = ib_dma_map_page(device, page, offset, size, DMA_TO_DEVICE);
	tx_desc->sge.lkey = rdma_stream->dma_mr->lkey;
	tx_desc->sge.length = size;

	err = dtr_post_tx_desc(rdma_stream, tx_desc);
	if (err)
		put_page(page);

	return err;
}

static bool dtr_hint(struct drbd_transport *transport, enum drbd_stream stream,
		enum drbd_tr_hints hint)
{
	switch (hint) {
	default: /* not implemented, but should not trigger error handling */
		return true;
	}
	return true;
}

static int __init dtr_init(void)
{
	return drbd_register_transport_class(&rdma_transport_class,
			DRBD_TRANSPORT_API_VERSION);
}

static void __exit dtr_cleanup(void)
{
	drbd_unregister_transport_class(&rdma_transport_class);
}

module_init(dtr_init)
module_exit(dtr_cleanup)
