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

struct drbd_rdma_stream {
	struct rdma_cm_id *cm_id;
	struct rdma_cm_id *child_cm_id; /* RCK: no clue what this is for... */

	struct ib_cq *recv_cq;
	struct ib_cq *send_cq;
	struct ib_pd *pd;
	struct ib_qp *qp;

	struct ib_mr *dma_mr;

	enum drbd_rdma_state state;
	wait_queue_head_t rdma_state_wq;
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

	/* list of to be freed and unmaped tx_descs, basically a FIFO, and its spin
	 * lock */
	struct list_head tx_descs;
	spinlock_t tx_list_lock;

	unsigned long recv_timeout;
	char name[8]; /* "control" or "data" */
};

struct drbd_rdma_transport {
	struct drbd_transport transport;
	struct drbd_rdma_stream *stream[2];
};

struct dtr_listener {
	struct drbd_listener listener;
	/* xxx */
};

struct dtr_waiter {
	struct drbd_waiter waiter;
	/* xxx */
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

static int dtr_post_tx_desc(struct drbd_rdma_stream *rdma_stream,
			    struct drbd_rdma_tx_desc *tx_desc, enum drbd_stream stream);
static int dtr_drain_rx_cq(struct drbd_rdma_stream *, struct drbd_rdma_rx_desc **, int);
static void dtr_recycle_rx_desc(struct drbd_rdma_stream *rdma_stream,
			       struct drbd_rdma_rx_desc *rx_desc);
static void dtr_refill_rx_desc(struct drbd_rdma_transport *rdma_transport,
			       enum drbd_stream stream);

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

	/* TODO: shutdown the connection */

	if (free_op == DESTROY_TRANSPORT) {
		kfree(rdma_transport);
		module_put(THIS_MODULE);
	}
}


static int dtr_send(struct drbd_transport *transport, enum drbd_stream stream, void *buf, size_t size, unsigned msg_flags)
{
	struct drbd_rdma_transport *rdma_transport =
		container_of(transport, struct drbd_rdma_transport, transport);

	struct drbd_rdma_stream *rdma_stream = rdma_transport->stream[stream];
	struct ib_device *device;
	struct drbd_rdma_tx_desc tx_desc;
	struct completion completion;

	if (stream == CONTROL_STREAM) {
		printk("send with CONTROL_STREAM\n");
	}
	else if (stream == DATA_STREAM){
		printk("send with DATA_STREAM\n");
	} else {
		printk("send with unknown STREAM!!!\n");
	}
	printk("send with data[0]:%x\n", ((char*)buf)[0]);

	device = rdma_stream->cm_id->device;
	tx_desc.type = SEND_MSG;
	tx_desc.completion = &completion;
	tx_desc.sge.addr = ib_dma_map_single(device, buf, size, DMA_TO_DEVICE);
	tx_desc.sge.lkey = rdma_stream->dma_mr->lkey;
	tx_desc.sge.length = size;

	init_completion(&completion);
	dtr_post_tx_desc(rdma_stream, &tx_desc, stream);
	wait_for_completion(&completion);

	return size;
}


static int _dtr_recv(struct drbd_transport *transport, enum drbd_stream stream, void **buf, size_t size, int flags, bool markconsumed);
static int dtr_recv_pages(struct drbd_peer_device *peer_device, struct page **pages, size_t size)
{
	/* struct drbd_rdma_transport *rdma_transport = */
	/* 	container_of(peer_device->connection->transport, struct drbd_rdma_transport, transport); */

	/* struct drbd_rdma_stream *rdma_stream = rdma_transport->stream[DATA_STREAM]; */
	struct page *all_pages, *page;
	int err = 0; /* RCK: for now fixed at 0 */
	int i = 0;
	/* struct drbd_rdma_rx_desc *rx_desc; */

	printk("RDMA: in recv_pages, size: %zu\n", size);
	all_pages = drbd_alloc_pages(peer_device, DIV_ROUND_UP(size, PAGE_SIZE), GFP_TRY);
	if (!all_pages)
		return -ENOMEM;
	page = all_pages;
	page_chain_for_each(page) {
		size_t len = min_t(int, size, PAGE_SIZE);
		void *data = kmap(page);
		/* while(dtr_drain_rx_data_cq(rdma_stream, &rx_desc, 1) == 0); */
		/* memcpy(data, rx_desc->data, len); */
		_dtr_recv(peer_device->connection->transport, DATA_STREAM, &data, len, CALLER_BUFFER, true);
		++i;
		kunmap(page);
		if (err < 0)
			goto fail;
		size -= len;
	}

	printk("rcvd %d pages\n", i);

	*pages = all_pages;
	return 0;
fail:
	drbd_free_pages(peer_device->device, all_pages, 0);
	return err;
}

static int _dtr_recv(struct drbd_transport *transport, enum drbd_stream stream, void **buf, size_t size, int flags, bool markconsumed)
{
	struct drbd_rdma_transport *rdma_transport =
		container_of(transport, struct drbd_rdma_transport, transport);

	struct drbd_rdma_stream *rdma_stream = rdma_transport->stream[stream];

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
			printk("RDMA: free %p and recv completely new on %s\n", rdma_stream->current_rx.desc, stream == CONTROL_STREAM ? "control": "data");
			dtr_recycle_rx_desc(rdma_stream, rdma_stream->current_rx.desc);
#if 0 /* RCK: for now I do not want any timeouts at all */
			printk("waiting for %lu\n", rdma_stream->recv_timeout);
			t = wait_event_interruptible_timeout(rdma_stream->recv_wq,
						dtr_drain_rx_cq(rdma_stream, &rx_desc, 1),
						rdma_stream->recv_timeout);
#else
			printk("waiting for very long\n");
			t = wait_event_interruptible_timeout(rdma_stream->recv_wq,
					dtr_drain_rx_cq(rdma_stream, &rx_desc, 1),
					10000*HZ);
#endif

			if (t <= 0)
			{
				if (t==0)
					printk("RDMA: recv() on %s timed out, ret: EAGAIN\n", stream == CONTROL_STREAM ? "control": "data");
				else
					printk("RDMA: recv() on %s timed out, ret: EINTR\n", stream == CONTROL_STREAM ? "control": "data");
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

			printk("RDMA: recv completely new fine, returning size on %s\n", stream == CONTROL_STREAM ? "control": "data");
			/* RCK: of course we need a better strategy, but for now, just add a new rx_desc if we consumed one... */
			printk("rx_count(%s): %d\n", rdma_stream->name, rdma_stream->rx_descs_posted);
			if (markconsumed)
				rdma_stream->current_rx.bytes_left = 0;

			dtr_refill_rx_desc(rdma_transport, stream);
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
			dtr_refill_rx_desc(rdma_transport, stream);
			return size;
		}

	return 0;
}

static int dtr_recv(struct drbd_transport *transport, enum drbd_stream stream, void **buf, size_t size, int flags)
{
	return _dtr_recv(transport, stream, buf, size, flags, false);
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
	struct drbd_rdma_stream *rdma_stream = cm_id->context;

	switch (event->event) {
	case RDMA_CM_EVENT_ADDR_RESOLVED:
		printk("RDMA(cma event): addr resolved\n");
		rdma_stream->state = ADDR_RESOLVED;
		err = rdma_resolve_route(cm_id, 2000);
		if (err) {
			printk("RDMA: rdma_resolve_route error %d\n", err);
			wake_up_interruptible(&rdma_stream->rdma_state_wq);
		}
		else {
			printk("RDMA: rdma_resolve_route OK\n");
		}
		break;

	case RDMA_CM_EVENT_ROUTE_RESOLVED:
		printk("RDMA(cma event): route resolved\n");
		rdma_stream->state = ROUTE_RESOLVED;
		wake_up_interruptible(&rdma_stream->rdma_state_wq);
		break;

	case RDMA_CM_EVENT_CONNECT_REQUEST:
		printk("RDMA(cma event): connect request\n");
		/* for listener */
		rdma_stream->state = CONNECT_REQUEST;
#if 1
		/* RCK: this is from the contribution, currently I do not see a need for it,
		 * but I keep "child_cm_id" in the struct for now */

		rdma_stream->child_cm_id = cm_id;
		printk("RDMA: child cma %p\n", rdma_stream->child_cm_id);
#endif
		wake_up_interruptible(&rdma_stream->rdma_state_wq);
		break;

	case RDMA_CM_EVENT_ESTABLISHED:
		printk("RDMA(cma event): established\n");
		rdma_stream->state = CONNECTED;
		wake_up_interruptible(&rdma_stream->rdma_state_wq);
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
		rdma_stream->state = ERROR;
		wake_up_interruptible(&rdma_stream->rdma_state_wq);
		break;

	case RDMA_CM_EVENT_DISCONNECTED:
		printk("RDMA(cma event) disconnect event\n");
		rdma_stream->state = DISCONNECTED;
		if ((rdma_stream->rx_descs_posted == 0) &&
		    (atomic_read(&rdma_stream->tx_descs_posted) == 0))
			wake_up_interruptible(&rdma_stream->rdma_state_wq);
		break;

	case RDMA_CM_EVENT_DEVICE_REMOVAL:
		printk("RDMA(cma event): detected device removal!\n");
		break;

	default:
		printk("RDMA(cma event): oof bad type!\n");
		wake_up_interruptible(&rdma_stream->rdma_state_wq);
		break;
	}
	return 0;
}

static int dtr_create_cm_id(struct drbd_rdma_stream *rdma_stream)
{

	rdma_stream->state = IDLE;
	init_waitqueue_head(&rdma_stream->rdma_state_wq);
	init_waitqueue_head(&rdma_stream->recv_wq);

	/* create CM id */
	rdma_stream->cm_id = rdma_create_id(
				dtr_cma_event_handler,
				rdma_stream, RDMA_PS_TCP, IB_QPT_RC);

#if 0 /* maybe add this tpye */
	drbd_info(rdma_transport, "RDMA: new cm id %p\n", rdma_transport->cm_id);
#else
	printk("RDMA: new cm id %p\n", rdma_stream->cm_id);
#endif
	if (!rdma_stream->cm_id) {
		return -ENOMEM;
	}

	return 0;
}

#if 0
/* RCK: do we need the following two functions twice (control/data)? */
static void dtr_rx_completion(struct drbd_rdma_stream *rdma_stream,
		struct drbd_rdma_rx_desc *desc, unsigned long xfer_len)
{
	ib_dma_sync_single_for_cpu(rdma_stream->cm_id->device, desc->dma_addr,
			RDMA_PAGE_SIZE, DMA_FROM_DEVICE);
	rdma_stream->rx_descs_posted--;

	printk("got buffer[0]: %x\n", desc->data[0]);
}
#endif

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
				ib_dma_sync_single_for_cpu(rdma_stream->cm_id->device, (*rx_desc)->dma_addr,
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

static void dtr_rx_control_cq_event_handler(struct ib_cq *cq, void *ctx)
{
	struct drbd_rdma_stream *rdma_stream = ctx;
	int ret;

	printk("RDMA (control): got rx cq event. state %d\n", rdma_stream->state);
	rdma_stream->rx_descs_posted--;

	/* dtr_create_and_post_rx_desc(rdma_stream); */

	wake_up_interruptible(&rdma_stream->recv_wq);
	ret = ib_req_notify_cq(cq, IB_CQ_NEXT_COMP);
	if (ret)
		printk("ib_req_notify_cq failed\n");
	else
		printk("ib_req_notify_cq success\n");
}

static void dtr_rx_data_cq_event_handler(struct ib_cq *cq, void *ctx)
{
	struct drbd_rdma_stream *rdma_stream = ctx;
	int ret;

	printk("RDMA (data): got rx cq event. state %d\n", rdma_stream->state);
	rdma_stream->rx_descs_posted--;

	/* dtr_create_and_post_rx_desc(rdma_stream); */

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
	int ret;
	struct drbd_rdma_tx_desc *tx_desc;
	unsigned long flags;

	printk("RDMA (%s): got tx cq event. state %d\n", rdma_stream->name, rdma_stream->state);

	atomic_dec(&rdma_stream->tx_descs_posted);

	spin_lock_irqsave(&rdma_stream->tx_list_lock, flags);
	tx_desc = list_first_entry_or_null(&rdma_stream->tx_descs, struct drbd_rdma_tx_desc, tx_entry);
	if (tx_desc)
		list_del(&tx_desc->tx_entry);
	spin_unlock_irqrestore(&rdma_stream->tx_list_lock, flags);

	if (tx_desc) {
		switch (tx_desc->type) {
		case SEND_PAGE:
			printk("put_page(%p), kfree(%p)\n", tx_desc->page, tx_desc);
			put_page(tx_desc->page);
			kfree(tx_desc);
			break;
		case SEND_MSG:
			printk("complete(%p)\n", tx_desc->completion);
			complete(tx_desc->completion);
			break;
		}
	} else {
		printk("RDMA: Something went terribly wrong, got tx completion event, but cannot find entry\n");
	}

	ret = ib_req_notify_cq(cq, IB_CQ_NEXT_COMP);
	if (ret)
		printk("ib_req_notify_cq failed\n");
	else
		printk("ib_req_notify_cq success\n");
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

	err = rdma_create_qp(rdma_stream->cm_id, rdma_stream->pd, &init_attr);
	if (err) {
		printk("RDMA: rdma_create_qp failed: %d\n", err);
		return err;
	}

	rdma_stream->qp = rdma_stream->cm_id->qp;
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

	ib_dma_sync_single_for_device(rdma_stream->cm_id->device,
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
	put_page(rx_desc->page);
	kfree(rx_desc);
}

/* RCK: for the first hack it is ok, but if we change the size of data in rx_desc, we
 * have to include "enum drbd_stream" as param */
static int dtr_create_some_rx_desc(struct drbd_rdma_stream *rdma_stream)
{
	struct drbd_rdma_rx_desc *rx_desc;
	struct ib_device *device = rdma_stream->cm_id->device;
	struct page *page;
	void *pos;
	int err, size, alloc_size = rdma_stream->rx_allocation_size;

	/* Should use drbd_alloc_pages() here. But that needs a peer_device.
	   Need to refactor that to be based on connections.
	page = drbd_alloc_pages(peer_device, 1, GFP_TRY);
	drbd_free_pages(peer_device->device, page, 0);
	*/

	page = alloc_page(GFP_KERNEL);
	if (!page)
		return -ENOMEM;

	pos = page_address(page);
	size = PAGE_SIZE;

	while (size) {
		rx_desc = kzalloc(sizeof(*rx_desc), GFP_KERNEL);
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
	struct ib_device *device = rdma_stream->cm_id->device;
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
static int dtr_post_tx_desc(struct drbd_rdma_stream *rdma_stream,
			    struct drbd_rdma_tx_desc *tx_desc, enum drbd_stream stream)
{
	struct ib_device *device = rdma_stream->cm_id->device;
	struct ib_send_wr send_wr, *send_wr_failed;
	int err;
	unsigned long flags;
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

	INIT_LIST_HEAD(&tx_desc->tx_entry);
	spin_lock_irqsave(&rdma_stream->tx_list_lock, flags);
	list_add_tail(&tx_desc->tx_entry, &rdma_stream->tx_descs);
	spin_unlock_irqrestore(&rdma_stream->tx_list_lock, flags);

	err = ib_post_send(rdma_stream->qp, &send_wr, &send_wr_failed);
	if (err) {
		printk("RDMA: ib_post_send failed\n");
		atomic_dec(&rdma_stream->tx_descs_posted);

		spin_lock_irqsave(&rdma_stream->tx_list_lock, flags);
		list_del(&tx_desc->tx_entry);
		spin_unlock_irqrestore(&rdma_stream->tx_list_lock, flags);
		return err;
	} else {
		/* printk("RDMA: ib_post_send successfull!\n"); */
		printk("Created send_wr (%p, %p): lkey=%x, addr=%llx, length=%d\n", tx_desc->page, tx_desc, tx_desc->sge.lkey, tx_desc->sge.addr, tx_desc->sge.length);
	}

	return 0;
}

/* allocate general resources for the stream (spin locks, lists, ...) */
static void dtr_alloc_stream_resources(struct drbd_rdma_stream *rdma_stream, enum drbd_stream stream)
{
	/* at least for now we keep the unused enum drbd_stream, in the future there
	 * might be a difference in the setup, dunno */

	rdma_stream->current_rx.desc = NULL;
	rdma_stream->current_rx.pos = NULL;
	rdma_stream->current_rx.bytes_left = 0;

	rdma_stream->recv_timeout = 1000 * HZ; /* RCK TODO: this should be the netconf value */

	INIT_LIST_HEAD(&rdma_stream->tx_descs);
	spin_lock_init(&rdma_stream->tx_list_lock);
	if (stream == DATA_STREAM) {
		strcpy(rdma_stream->name, "data");
		rdma_stream->rx_allocation_size = DRBD_SOCKET_BUFFER_SIZE; /* 4096 usually PAGE_SIZE */
	} else {
		strcpy(rdma_stream->name, "control");
		rdma_stream->rx_allocation_size = DRBD_SOCKET_BUFFER_SIZE; /* 4096 usually PAGE_SIZE */
	}
	/* TODO: rx_allocation_size should be hintend from DRBD to the transport! */

}

/* allocate rdma specific resources for the stream */
static int dtr_alloc_rdma_resources(struct drbd_rdma_transport *rdma_transport, enum drbd_stream stream)
{
	struct drbd_rdma_stream *rdma_stream = rdma_transport->stream[stream];
	int err;

	void (*rx_event_handler)(struct ib_cq *, void *);
	void (*tx_event_handler)(struct ib_cq *, void *);

	tx_event_handler = dtr_tx_cq_event_handler;
	if (stream == DATA_STREAM) {
		rx_event_handler = dtr_rx_data_cq_event_handler;
	} else {
		rx_event_handler = dtr_rx_control_cq_event_handler;
	}

	printk("RDMA: here with cm_id: %p\n", rdma_stream->cm_id);

	/* alloc protection domain (PD) */
	rdma_stream->pd = ib_alloc_pd(rdma_stream->cm_id->device);
	if (IS_ERR(rdma_stream->pd)) {
		printk("RDMA: ib_alloc_pd failed\n");
		err = PTR_ERR(rdma_stream->pd);
		goto pd_failed;
	}
	printk("RDMA: created pd %p\n", rdma_stream->pd);

	/* create recv completion queue (CQ) */
	rdma_stream->recv_cq = ib_create_cq(rdma_stream->cm_id->device,
		rx_event_handler, NULL, rdma_stream, RDMA_MAX_RX, 0);
	if (IS_ERR(rdma_stream->recv_cq)) {
		printk("RDMA: ib_create_cq recv failed\n");
		err = PTR_ERR(rdma_stream->recv_cq);
		goto recv_cq_failed;
	}
	printk("RDMA: created recv cq %p\n", rdma_stream->recv_cq);

	/* create send completion queue (CQ) */
	rdma_stream->send_cq = ib_create_cq(rdma_stream->cm_id->device,
		tx_event_handler, NULL, rdma_stream, RDMA_MAX_TX, 0);
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

	dtr_refill_rx_desc(rdma_transport, stream);

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


static int dtr_free_stream(struct drbd_rdma_stream *rdma_stream)
{
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
	if (rdma_stream->cm_id)
		rdma_destroy_id(rdma_stream->cm_id);

	kfree(rdma_stream);
	rdma_stream = NULL;
#if 0
	rdma_stream->dma_mr = NULL;
	rdma_stream->qp = NULL;
	rdma_stream->send_cq = NULL;
	rdma_stream->recv_cq = NULL;
	rdma_stream->pd = NULL;
#endif

	return 0;
}

static int dtr_free_resources(struct drbd_rdma_transport *rdma_transport)
{
	int err;

	err = dtr_free_stream(rdma_transport->stream[DATA_STREAM]);
	err |= dtr_free_stream(rdma_transport->stream[CONTROL_STREAM]);
	if (err)
		return -1;

	return 0;
}

static int dtr_connect_stream(struct drbd_rdma_transport *rdma_transport, struct sockaddr_in *peer_addr, enum drbd_stream stream)
{
	struct drbd_rdma_stream *rdma_stream = rdma_transport->stream[stream];
	struct rdma_conn_param conn_param;
	struct sockaddr_in *peer_addr_in;
	int err;

	/* RCK: fix up this sockaddr cast mess/ipv6 hocus pocus */
	peer_addr_in = (struct sockaddr_in *)peer_addr;
	printk("RDMA: entering connect for %s\n", (stream == DATA_STREAM ? "DATA_STREAM" : "CONTROL_STREAM"));
	printk("RDMA: connecting %pI4 port %d\n", &peer_addr_in->sin_addr, ntohs(peer_addr_in->sin_port));

	err = dtr_create_cm_id(rdma_stream);
	if (err) {
		printk("rdma create id error %d\n", err);
		return -EINTR;
	}

	err = rdma_resolve_addr(rdma_stream->cm_id, NULL,
			(struct sockaddr *) peer_addr_in,
			2000);

	if (err) {
		printk("RDMA: rdma_resolve_addr error %d\n", err);
		return err;
	}

	wait_event_interruptible(rdma_stream->rdma_state_wq,
			rdma_stream->state >= ROUTE_RESOLVED);

	if (rdma_stream->state != ROUTE_RESOLVED) {
		printk("RDMA addr/route resolution error. state %d\n", rdma_stream->state);
		return err;
	}
	printk("route resolve OK\n");

	err = dtr_alloc_rdma_resources(rdma_transport, stream);
	if (err) {
		printk("RDMA: failed allocating resources %d\n", err);
		return err;
	}
	printk("RDMA: allocate resources: OK\n");

	/* Connect peer */
	memset(&conn_param, 0, sizeof conn_param);
	conn_param.responder_resources = 1;
	conn_param.initiator_depth = 1;
	conn_param.retry_count = 10;

	err = rdma_connect(rdma_stream->cm_id, &conn_param);
	if (err) {
		printk("RDMA: rdma_connect error %d\n", err);
		return err;
	}

	wait_event_interruptible(rdma_stream->rdma_state_wq,
			rdma_stream->state >= CONNECTED);
	if (rdma_stream->state == ERROR) {
		printk("RDMA: failed connecting. state %d\n", rdma_stream->state);
		return err;
	}
	printk("RDMA: rdma_connect successful\n");

	printk("RDMA: returning from connect for %s\n", (stream == DATA_STREAM ? "DATA_STREAM" : "CONTROL_STREAM"));

	return 0;
}

/* bla == Bind Listen Accept */
static int dtr_bla_stream(struct drbd_rdma_transport *rdma_transport, struct sockaddr_in *my_addr, enum drbd_stream stream)
{
	struct drbd_rdma_stream *rdma_stream = rdma_transport->stream[stream];
	int err;
	struct rdma_conn_param conn_param;

	printk("RDMA: entering BLA for %s\n", (stream == DATA_STREAM ? "DATA_STREAM" : "CONTROL_STREAM"));
	printk("RDMA: BLA %pI4 port %d\n", &my_addr->sin_addr, ntohs(my_addr->sin_port));

	err = dtr_create_cm_id(rdma_stream);
	if (err) {
		printk("RDMA: rdma create id error %d\n", err);
		return -EINTR;
	}

	err = rdma_bind_addr(rdma_stream->cm_id, (struct sockaddr *) my_addr);

	if (err) {
		printk("RDMA: rdma_bind_addr error %d\n", err);
		return err;
	}

	printk("RDMA: bind success\n");

	err = rdma_listen(rdma_stream->cm_id, 3);
	if (err) {
		printk("RDMA: rdma_listen error %d\n", err);
		return err;
	}
	printk("RDMA: listen success\n");

	wait_event_interruptible(rdma_stream->rdma_state_wq,
				 rdma_stream->state >= CONNECT_REQUEST);

	if (rdma_stream->state != CONNECT_REQUEST) {
		printk("RDMA: connect request error. state %d\n", rdma_stream->state);
		return err;
	}
	printk("RDMA: connect request success\n");

#if 1
	/* RCK: Again, from the contribution. Let's see if we need it */
   /* drbd_rdma_destroy_id(rdma_conn); */
	if (rdma_stream->cm_id)
		rdma_destroy_id(rdma_stream->cm_id);
	rdma_stream->cm_id = NULL;

	rdma_stream->cm_id = rdma_stream->child_cm_id;
	rdma_stream->child_cm_id = NULL;
#endif

	err = dtr_alloc_rdma_resources(rdma_transport, stream);
	if (err) {
		printk("RDMA failed allocating resources %d\n", err);
		return err;
	}
	printk("RDMA: allocated resources\n");

	memset(&conn_param, 0, sizeof conn_param);
	conn_param.responder_resources = 1;
	conn_param.initiator_depth = 1;

	err = rdma_accept(rdma_stream->cm_id, &conn_param);
	if (err) {
	    printk("RDMA: rdma_accept error %d\n", err);
	    return err;
	}
	printk("RMDA: connection accepted\n");

	return 0;
}


/* RCK: this way of connect requires IBoIP, but I guess that is an assumption we can make
 * If this beast will ever work, we can think about all the other ways/possible fallbacks */
static int dtr_connect(struct drbd_transport *transport)
{
	struct drbd_rdma_transport *rdma_transport =
		container_of(transport, struct drbd_rdma_transport, transport);

	struct drbd_connection *connection;
	struct sockaddr_in *peer_addr, *my_addr;
	struct drbd_rdma_stream *rdma_stream;
	int err;

	connection = transport->connection;

	/* Assume that the peer only understands protocol 80 until we know better.  */
	connection->agreed_pro_version = 80;

	peer_addr = (struct sockaddr_in *)&connection->peer_addr;
	my_addr = (struct sockaddr_in *)&connection->my_addr;

	rdma_stream = kzalloc(sizeof(*rdma_stream), GFP_KERNEL);
	rdma_transport->stream[CONTROL_STREAM] = rdma_stream;
	dtr_alloc_stream_resources(rdma_stream, CONTROL_STREAM);

	/* RCK: that is of course crazy, but just a hackaround for testing until I
	 * rewrite the connection logic, rdma_server is a module param: */

	if (rdma_server)
		err = dtr_bla_stream(rdma_transport, my_addr, CONTROL_STREAM);
	else
		err = dtr_connect_stream(rdma_transport, peer_addr, CONTROL_STREAM);


	rdma_stream = kzalloc(sizeof(*rdma_stream), GFP_KERNEL);
	rdma_transport->stream[DATA_STREAM] = rdma_stream;
	dtr_alloc_stream_resources(rdma_stream, DATA_STREAM);

	if (rdma_server) {
		my_addr->sin_port += 1; /* +1 in network order, "works for me on rum/kugel" */
		err |= dtr_bla_stream(rdma_transport, my_addr, DATA_STREAM);
	}
	else {
		peer_addr->sin_port += 1;
		schedule_timeout_uninterruptible(HZ);
		err |= dtr_connect_stream(rdma_transport, peer_addr, DATA_STREAM);
	}

	if (!err) {
		char *buf = kzalloc(sizeof(*buf) * RDMA_PAGE_SIZE, GFP_KERNEL);
		printk("RDMA: both %s streams established\n", rdma_server ? "server" : "client");
		if (rdma_server) {
			memset(buf, 0x55, RDMA_PAGE_SIZE);
			dtr_send(transport, DATA_STREAM, buf, 2, 0);
			err = dtr_recv(transport, DATA_STREAM, (void **)&buf, 1, CALLER_BUFFER);
			if (buf[0] == 0x56)
				printk("RDMA startup (server), HANDSHAKE OK\n");
			err = dtr_recv(transport, DATA_STREAM, (void **)&buf, 1, CALLER_BUFFER);
		} else {
			memset(buf, 0x56, RDMA_PAGE_SIZE);
			dtr_send(transport, DATA_STREAM, buf, 2, 0);
			err = dtr_recv(transport, DATA_STREAM, (void **)&buf, 1, CALLER_BUFFER);
			 if (buf[0] == 0x55)
				 printk("RDMA startup (client), HANDSHAKE OK\n");
			 err = dtr_recv(transport, DATA_STREAM, (void **)&buf, 1, CALLER_BUFFER);
		}
		kfree(buf);
		printk("connect returns 0\n");
		return 0;
	}
	else
		printk("RDMA: connection not established :-/\n");

	if (err) /* RCK: guess it is assumed that connect() retries until successful, handle that later */
		goto out;

#if 0 /* RCK: just copied from tcp_transport, guess we will need that */
	/* Assume that the peer only understands protocol 80 until we know better.  */

	waiter.waiter.connection = connection;
	waiter.socket = NULL;
	if (drbd_get_listener(&waiter.waiter, dtt_create_listener))
		return -EAGAIN;
#endif

	printk("connect returns 0\n");
	return 0;

out:
	dtr_free_resources(rdma_transport);
	return -EINTR;
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

static bool dtr_stream_ok(struct drbd_transport *transport, enum drbd_stream stream)
{
	struct drbd_rdma_transport *rdma_transport =
		container_of(transport, struct drbd_rdma_transport, transport);

	/* RCK: Not sure if it is a valid assumption that the stream is OK as long
	 * as the CM knows about it, but for now my best guess */
	return rdma_transport->stream[stream] && rdma_transport->stream[stream]->cm_id;
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
	device = rdma_stream->cm_id->device;
	tx_desc->type = SEND_PAGE;
	tx_desc->page = page;
	tx_desc->sge.addr = ib_dma_map_page(device, page, offset, size, DMA_TO_DEVICE);
	tx_desc->sge.lkey = rdma_stream->dma_mr->lkey;
	tx_desc->sge.length = size;

	err = dtr_post_tx_desc(rdma_stream, tx_desc, stream);
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
