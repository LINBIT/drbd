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

#undef pr_fmt
#define pr_fmt(fmt)	"drbd_rdma: " fmt

#include <linux/module.h>
#include <drbd_transport.h>
#include <rdma/ib_verbs.h>
#include <rdma/rdma_cm.h>
#include "drbd_int.h"

/* Nearly all data transfer uses the send/receive semantics. No need to
   actually use RDMA WRITE / READ.

   Only for DRBD's remote read (P_DATA_REQUEST and P_DATA_REPLY) a
   RDMA WRITE would make a lot of sense:
     Right now the recv_dless_read() function in DRBD is one of the few
     remaining callers of recv(,,CALLER_BUFFER). This in turn needs a
     memcpy().

   The block_id field (64 bit) could be re-labelled to be the RKEY for
   an RDMA WRITE. The P_DATA_REPLY packet will then only deliver the
   news that the RDMA WRITE was executed...


   Flow Control
   ============

   If the receiving machine can not keep up with the data rate it needs to
   slow down the sending machine. In order to do so we keep track of the
   number of rx_descs the peer has posted (peer_rx_descs).

   If one player posts new rx_descs it tells the peer about it with a
   dtr_flow_control packet. Those packet get never delivered to the
   DRBD above us.
*/

MODULE_AUTHOR("Roland Kammerer <roland.kammerer@linbit.com>");
MODULE_AUTHOR("Philipp Reisner <philipp.reisner@linbit.com>");
MODULE_DESCRIPTION("RDMA transport layer for DRBD");
MODULE_LICENSE("GPL");

/* If no recvbuf_size or sendbuf_size is configured use 512KiB for the DATA_STREAM */
/* Actually it is not a buffer, but the number of tx_descs or rx_descs we allow,
   very comparable to the socket sendbuf and recvbuf sizes */
#define RDMA_DEF_BUFFER_SIZE (1 << 19)

#define DTR_MAGIC ((u32)0x5257494E)

struct dtr_flow_control {
	uint32_t magic;
	uint32_t new_rx_descs[2];
} __packed;

enum drbd_rdma_state {
	IDLE = 1,
	CONNECT_REQUEST,
	ADDR_RESOLVED,
	ROUTE_RESOLVED,
	CONNECTED,
	DISCONNECTED,
	ERROR
};

struct drbd_rdma_rx_desc {
	struct page *page;
	void *data;
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
		void *data;
	};
	struct ib_sge sge;
	struct list_head tx_entry;
};

struct dtr_cm {
	struct rdma_cm_id *id;
	enum drbd_rdma_state state;
	wait_queue_head_t state_wq;
	char name[8]; /* debugging purpose */
};

struct drbd_rdma_stream {
	struct dtr_cm cm;

	struct ib_cq *recv_cq;
	struct ib_cq *send_cq;
	struct ib_pd *pd;
	struct ib_qp *qp;

	struct ib_mr *dma_mr;

	wait_queue_head_t send_wq;
	atomic_t tx_descs_posted;
	int tx_descs_max; /* derived from net_conf->sndbuf_size. Do not change after alloc. */
	long send_timeout;
	atomic_t peer_rx_descs; /* peer's receive window in number of rx descs */

	wait_queue_head_t recv_wq;
	int rx_descs_posted;
	int rx_descs_max;  /* derived from net_conf->rcvbuf_size. Do not change after alloc. */

	int rx_descs_allocated;
	int rx_descs_want_posted;
	atomic_t rx_descs_unread;

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

	long recv_timeout;
	char name[8]; /* "control" or "data" */
	struct drbd_rdma_transport *rdma_transport;
};

struct drbd_rdma_transport {
	struct drbd_transport transport;
	struct drbd_rdma_stream *stream[2];
};

struct dtr_listener {
	struct drbd_listener listener;

	struct dtr_cm cm;
	struct rdma_cm_id *child_cms; /* Single linked list on the context member */
};

struct dtr_waiter {
	struct drbd_waiter waiter;

	struct drbd_rdma_stream *rdma_stream; /* to pass streams between waiters... */
};

static int stream_nr = 0; /* debugging */

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
static bool dtr_receive_rx_desc(struct drbd_rdma_stream *, struct drbd_rdma_rx_desc **);
static void dtr_recycle_rx_desc(struct drbd_rdma_stream *rdma_stream,
				struct drbd_rdma_rx_desc **pp_rx_desc);
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

	for (i = DATA_STREAM; i <= CONTROL_STREAM; i++) {
		dtr_free_stream(rdma_transport->stream[i]);
		rdma_transport->stream[i] = NULL;
	}

	if (free_op == DESTROY_TRANSPORT) {
		kfree(rdma_transport);
		module_put(THIS_MODULE);
	}
}


static int dtr_send(struct drbd_rdma_stream *rdma_stream, void *buf, size_t size)
{
	struct ib_device *device;
	struct drbd_rdma_tx_desc *tx_desc;
	void *send_buffer;

	// pr_info("%s: dtr_send() size = %d data[0]:%x\n", rdma_stream->name, (int)size, ((char*)buf)[0]);

	tx_desc = kzalloc(sizeof(*tx_desc), GFP_NOIO);
	if (!tx_desc)
		return -ENOMEM;

	send_buffer = kmalloc(size, GFP_NOIO);
	if (!send_buffer) {
		kfree(tx_desc);
		return -ENOMEM;
	}
	memcpy(send_buffer, buf, size);

	device = rdma_stream->cm.id->device;
	tx_desc->type = SEND_MSG;
	tx_desc->data = send_buffer;
	tx_desc->sge.addr = ib_dma_map_single(device, send_buffer, size, DMA_TO_DEVICE);
	tx_desc->sge.lkey = rdma_stream->dma_mr->lkey;
	tx_desc->sge.length = size;

	dtr_post_tx_desc(rdma_stream, tx_desc);

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
	int i = 0;

	if (rdma_stream->cm.state > CONNECTED)
		return -ECONNRESET;

	// pr_info("%s: in recv_pages, size: %zu\n", rdma_stream->name, size);
	D_ASSERT(peer_device, rdma_stream->current_rx.bytes_left == 0);
	dtr_recycle_rx_desc(rdma_stream, &rdma_stream->current_rx.desc);

	while (size) {
		struct drbd_rdma_rx_desc *rx_desc = NULL;
		long t;

		t = wait_event_interruptible_timeout(rdma_stream->recv_wq,
					dtr_receive_rx_desc(rdma_stream, &rx_desc),
					rdma_stream->recv_timeout);

		if (t <= 0) {
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
	// pr_info("%s: rcvd %d pages\n", rdma_stream->name, i);
	atomic_add(i, &peer_device->device->pp_in_use);
	*pages = all_pages;
	return 0;
}

static int _dtr_recv(struct drbd_rdma_stream *rdma_stream, void **buf, size_t size, int flags)
{
	struct drbd_rdma_rx_desc *rx_desc = NULL;
	void *buffer;

	if (flags & GROW_BUFFER) {
		/* Since transport_rdma always returns the full, requested amount
		   of data, DRBD should never call with GROW_BUFFER! */
		pr_err("Called with GROW_BUFFER\n");
		return -EINVAL;
	} else if (rdma_stream->current_rx.bytes_left == 0) {
		long t;

		dtr_recycle_rx_desc(rdma_stream, &rdma_stream->current_rx.desc);
		if (flags & MSG_DONTWAIT) {
			t = dtr_receive_rx_desc(rdma_stream, &rx_desc);
		} else {
			t = wait_event_interruptible_timeout(rdma_stream->recv_wq,
						dtr_receive_rx_desc(rdma_stream, &rx_desc),
						rdma_stream->recv_timeout);
		}

		if (t <= 0)
			return t == 0 ? -EAGAIN : -EINTR;

		// pr_info("%s: got a new page with size: %d\n", rdma_stream->name, rx_desc->size);
		buffer = rx_desc->data;
		rdma_stream->current_rx.desc = rx_desc;
		rdma_stream->current_rx.pos = buffer + size;
		rdma_stream->current_rx.bytes_left = rx_desc->size - size;
		if (rdma_stream->current_rx.bytes_left < 0)
			pr_warn("%s: new, requesting more (%zu) than available (%d)\n",
				rdma_stream->name, size, rx_desc->size);

		if (flags & CALLER_BUFFER)
			memcpy(*buf, buffer, size);
		else
			*buf = buffer;

		// pr_info("%s: recv completely new fine, returning size on\n", rdma_stream->name);
		// pr_info("%s: rx_count: %d\n", rdma_stream->name, rdma_stream->rx_descs_posted);

		return size;
	} else { /* return next part */
		// pr_info("recv next part on %s\n", rdma_stream->name);
		buffer = rdma_stream->current_rx.pos;
		rdma_stream->current_rx.pos += size;

		if (rdma_stream->current_rx.bytes_left < size) {
			pr_err("%s: requested more than left! bytes_left = %d, size = %zu\n",
			       rdma_stream->name, rdma_stream->current_rx.bytes_left, size);
			rdma_stream->current_rx.bytes_left = 0; /* 0 left == get new entry */
		} else {
			rdma_stream->current_rx.bytes_left -= size;
			// pr_info("%s: old_rx left: %d\n", rdma_stream->name, rdma_stream->current_rx.bytes_left);
		}

		if (flags & CALLER_BUFFER)
			memcpy(*buf, buffer, size);
		else
			*buf = buffer;

		// pr_info("%s: recv next part fine, returning size\n", rdma_stream->name);
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

	if (rdma_stream->cm.state > CONNECTED)
		return -ECONNRESET;

	err = _dtr_recv(rdma_stream, buf, size, flags);

	dtr_refill_rx_desc(rdma_transport, stream);
	return err;
}

static void dtr_stats(struct drbd_transport* transport, struct drbd_transport_stats *stats)
{
	struct drbd_rdma_transport *rdma_transport =
		container_of(transport, struct drbd_rdma_transport, transport);
	struct drbd_rdma_stream *rdma_stream = rdma_transport->stream[DATA_STREAM];
	atomic_t *tx_descs_posted = &rdma_stream->tx_descs_posted;

	/* these are used by the sender, guess we should them get right */
	stats->send_buffer_size = rdma_stream->tx_descs_max * DRBD_SOCKET_BUFFER_SIZE;
	stats->send_buffer_used = atomic_read(tx_descs_posted) * DRBD_SOCKET_BUFFER_SIZE;

	/* these two for debugfs */
	stats->unread_received = atomic_read(&rdma_stream->rx_descs_unread) * DRBD_SOCKET_BUFFER_SIZE;
	stats->unacked_send = stats->send_buffer_used;

}

static int dtr_cma_event_handler(struct rdma_cm_id *cm_id, struct rdma_cm_event *event)
{
	int err;
	/* context comes from rdma_create_id() */
	struct dtr_cm *cm_context = cm_id->context;
	struct dtr_listener *listener;
	struct drbd_waiter *waiter;

	switch (event->event) {
	case RDMA_CM_EVENT_ADDR_RESOLVED:
		// pr_info("%s: RDMA_CM_EVENT_ADDR_RESOLVED\n", cm_context->name);
		cm_context->state = ADDR_RESOLVED;
		err = rdma_resolve_route(cm_id, 2000);
		if (err)
			pr_err("RDMA: rdma_resolve_route error %d\n", err);
		wake_up_interruptible(&cm_context->state_wq);
		break;

	case RDMA_CM_EVENT_ROUTE_RESOLVED:
		// pr_info("%s: RDMA_CM_EVENT_ROUTE_RESOLVED\n", cm_context->name);
		cm_context->state = ROUTE_RESOLVED;
		wake_up_interruptible(&cm_context->state_wq);
		break;

	case RDMA_CM_EVENT_CONNECT_REQUEST:
		// pr_info("%s: RDMA_CM_EVENT_CONNECT_REQUEST\n", cm_context->name);
		/* for listener */
		cm_context->state = CONNECT_REQUEST;

		listener = container_of(cm_context, struct dtr_listener, cm);

		spin_lock(&listener->listener.resource->listeners_lock);
		listener->listener.pending_accepts++;
		waiter = list_entry(listener->listener.waiters.next, struct drbd_waiter, list);

		/* I found this a bit confusing. When a new connection comes in, the callback
		   gets called with a new rdma_cm_id. The new rdma_cm_id inherits its context
		   pointer from the listening rdma_cm_id. We will create a new context later */

		/* Insert the fresh cm_id it at the head of the list child_cms */
		cm_id->context = listener->child_cms;
		listener->child_cms = cm_id;

		/* set cm_id to the listener */
		cm_id = cm_context->id;

		wake_up(&waiter->wait); /* wake an arbitrary waiter */
		spin_unlock(&listener->listener.resource->listeners_lock);
		break;

	case RDMA_CM_EVENT_ESTABLISHED:
		// pr_info("%s: RDMA_CM_EVENT_ESTABLISHED\n", cm_context->name);
		cm_context->state = CONNECTED;
		wake_up_interruptible(&cm_context->state_wq);
		break;

	case RDMA_CM_EVENT_ADDR_ERROR:
		// pr_info("%s: RDMA_CM_EVENT_ADDR_ERROR\n", cm_context->name);
	case RDMA_CM_EVENT_ROUTE_ERROR:
		// pr_info("%s: RDMA_CM_EVENT_ROUTE_ERROR\n", cm_context->name);
	case RDMA_CM_EVENT_CONNECT_ERROR:
		// pr_info("%s: RDMA_CM_EVENT_CONNECT_ERROR\n", cm_context->name);
	case RDMA_CM_EVENT_UNREACHABLE:
		// pr_info("%s: RDMA_CM_EVENT_UNREACHABLE\n", cm_context->name);
	case RDMA_CM_EVENT_REJECTED:
		// pr_info("%s: RDMA_CM_EVENT_REJECTED\n", cm_context->name);
		// pr_info("event = %d, status = %d\n", event->event, event->status);
		cm_context->state = ERROR;
		wake_up_interruptible(&cm_context->state_wq);
		break;

	case RDMA_CM_EVENT_DISCONNECTED:
		// pr_info("%s: RDMA_CM_EVENT_DISCONNECTED\n", cm_context->name);
		cm_context->state = DISCONNECTED;
		wake_up_interruptible(&cm_context->state_wq);
		break;

	case RDMA_CM_EVENT_DEVICE_REMOVAL:
		// pr_info("%s: RDMA_CM_EVENT_DEVICE_REMOVAL\n", cm_context->name);
		break;

	default:
		pr_warn("RDMA(cma event): oof bad type!\n");
		wake_up_interruptible(&cm_context->state_wq);
		break;
	}
	return 0;
}

static int dtr_create_cm_id(struct dtr_cm *cm_context)
{
	cm_context->state = IDLE;
	init_waitqueue_head(&cm_context->state_wq);

	cm_context->id = rdma_create_id(dtr_cma_event_handler,
					cm_context, RDMA_PS_TCP, IB_QPT_RC);

	return cm_context->id ? 0 : -ENOMEM;
}

static bool __dtr_receive_rx_desc(struct drbd_rdma_stream *rdma_stream, struct drbd_rdma_rx_desc **rx_desc)
{
	struct ib_cq *cq = rdma_stream->recv_cq;
	struct ib_wc wc;
	int size;

	if (ib_poll_cq(cq, 1, &wc) == 1) {
		rdma_stream->rx_descs_posted--;
		atomic_dec(&rdma_stream->rx_descs_unread);
		*rx_desc = (struct drbd_rdma_rx_desc *) (unsigned long) wc.wr_id;
		WARN_ON(rx_desc == NULL);

		if(wc.status == IB_WC_SUCCESS) {
			if (wc.opcode == IB_WC_RECV) {
				size = wc.byte_len;
				ib_dma_sync_single_for_cpu(rdma_stream->cm.id->device, (*rx_desc)->dma_addr,
						(*rx_desc)->size, DMA_FROM_DEVICE);
				(*rx_desc)->size = size;
				// pr_info("%s: in drain: %p, size = %d, data[0]:%x\n", rdma_stream->name, rx_desc, size, (*rx_desc)->data[0]);
			} else
				pr_warn("%s: WC SUCCESS, but strange opcode... %d\n", rdma_stream->name, wc.opcode);

			return true;
		} else {
			pr_err("%s: rx_drain: wc.status != IB_WC_SUCCESS %d\n", rdma_stream->name, wc.status);
		}
	}

	return false;
}

static void dtr_got_flow_control_msg(struct drbd_rdma_stream *rdma_stream,
				     struct dtr_flow_control *msg)
{
	struct drbd_rdma_transport *rdma_transport = rdma_stream->rdma_transport;
	int i;

	for (i = DATA_STREAM; i <= CONTROL_STREAM; i++) {
		uint32_t new_rx_descs = be32_to_cpu(msg->new_rx_descs[i]);
		rdma_stream = rdma_transport->stream[i];

		atomic_add(new_rx_descs, &rdma_stream->peer_rx_descs);
	}
}

static bool dtr_receive_rx_desc(struct drbd_rdma_stream *rdma_stream,
				struct drbd_rdma_rx_desc **pp_rx_desc)
{
	struct drbd_rdma_rx_desc *rx_desc;
	bool r;

	while (1) {
		r = __dtr_receive_rx_desc(rdma_stream, &rx_desc);
		if (!r)
			return false;

		if (*(uint32_t *)rx_desc->data == cpu_to_be32(DTR_MAGIC)) {
			dtr_got_flow_control_msg(rdma_stream, rx_desc->data);
			dtr_recycle_rx_desc(rdma_stream, &rx_desc);
			continue;
		}
		*pp_rx_desc = rx_desc;
		return true;
	}
}

static void dtr_rx_cq_event_handler(struct ib_cq *cq, void *ctx)
{
	struct drbd_rdma_stream *rdma_stream = ctx;
	int ret;

	// pr_info("%s: got rx cq event. state %d\n", rdma_stream->name, rdma_stream->cm.state);
	atomic_inc(&rdma_stream->rx_descs_unread);

	wake_up_interruptible(&rdma_stream->recv_wq);
	ret = ib_req_notify_cq(cq, IB_CQ_NEXT_COMP);
	if (ret)
		pr_err("%s: ib_req_notify_cq failed\n", rdma_stream->name);

}

static void dtr_tx_cq_event_handler(struct ib_cq *cq, void *ctx)
{
	struct drbd_rdma_stream *rdma_stream = ctx;
	struct ib_device *device = rdma_stream->cm.id->device;
	struct drbd_rdma_tx_desc *tx_desc;
	struct ib_wc wc;
	int ret;

	// pr_info("%s: got tx cq event. state %d\n", rdma_stream->name, rdma_stream->cm.state);

	ret = ib_req_notify_cq(cq, IB_CQ_NEXT_COMP);
	if (ret)
		pr_err("ib_req_notify_cq failed\n");

	/* Alternatively put them onto a list here, and do the processing (freeing)
	   at a later point in time. Probably resource freeing is cheap enough to do
	   it directly here. */
	while ((ret = ib_poll_cq(cq, 1, &wc)) == 1) {
		atomic_dec(&rdma_stream->tx_descs_posted);

		if (wc.status != IB_WC_SUCCESS) {
			pr_err("%s: tx_event: wc.status != IB_WC_SUCCESS %d\n", rdma_stream->name, wc.status);
			goto disconnect;
		}

		if (wc.opcode != IB_WC_SEND) {
			pr_err("%s: wc.opcode != IB_WC_SEND %d\n", rdma_stream->name, wc.opcode);
			goto disconnect;
		}

		tx_desc = (struct drbd_rdma_tx_desc *) (unsigned long) wc.wr_id;

		switch (tx_desc->type) {
		case SEND_PAGE:
			ib_dma_unmap_page(device, tx_desc->sge.addr, tx_desc->sge.length, DMA_TO_DEVICE);
			put_page(tx_desc->page);
			break;
		case SEND_MSG:
			ib_dma_unmap_single(device, tx_desc->sge.addr, tx_desc->sge.length, DMA_TO_DEVICE);
			kfree(tx_desc->data);
			break;
		}
		kfree(tx_desc);
	}

	if (ret != 0)
		pr_warn("%s: ib_poll_cq() returned %d\n", rdma_stream->name, ret);

	if (0) {
disconnect:
		rdma_stream->cm.state = ERROR;
	}

	wake_up_interruptible(&rdma_stream->send_wq);
}

static int dtr_create_qp(struct drbd_rdma_stream *rdma_stream)
{
	int err;
	struct ib_qp_init_attr init_attr = {
		.cap.max_send_wr = rdma_stream->tx_descs_max,
		.cap.max_recv_wr = rdma_stream->rx_descs_max,
		.cap.max_recv_sge = 1,
		.cap.max_send_sge = 1,
		.qp_type = IB_QPT_RC,
		.send_cq = rdma_stream->send_cq,
		.recv_cq = rdma_stream->recv_cq,
		.sq_sig_type = IB_SIGNAL_REQ_WR
	};

	err = rdma_create_qp(rdma_stream->cm.id, rdma_stream->pd, &init_attr);
	if (err) {
		pr_err("%s: rdma_create_qp failed: %d\n", rdma_stream->name, err);
		return err;
	}

	rdma_stream->qp = rdma_stream->cm.id->qp;
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
			rx_desc->dma_addr, rx_desc->size, DMA_FROM_DEVICE);

	rdma_stream->rx_descs_posted++;
	err = ib_post_recv(rdma_stream->qp, &recv_wr, &recv_wr_failed);
	if (err) {
		pr_err("%s: ib_post_recv error %d\n", rdma_stream->name, err);
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
			pr_err("%s: dtr_post_rx_desc() returned %d\n", rdma_stream->name, err);
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
	struct drbd_rdma_stream *rdma_stream = rdma_transport->stream[stream];
	int descs_want_posted, descs_max;

	descs_max = rdma_stream->rx_descs_max;
	/* The above statement is obvious for the DATA_STREAM. We use the same
	   number of descriptors for the CONTROL_STREAM as well, though that
	   covers only a 64th fraction of the size in bytes available. I.e.
	   by default two pages. */

	descs_want_posted = rdma_stream->rx_descs_want_posted;

	while (rdma_stream->rx_descs_posted < descs_want_posted &&
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
				struct drbd_rdma_rx_desc **pp_rx_desc)
{
	int max_posted = rdma_stream->rx_descs_max;
	struct drbd_rdma_rx_desc *rx_desc = *pp_rx_desc;

	if (!rx_desc)
		return;

	if (rdma_stream->rx_descs_posted >= max_posted)
		dtr_free_rx_desc(rdma_stream, rx_desc);
	else
		dtr_repost_rx_desc(rdma_stream, rx_desc);

	*pp_rx_desc = NULL;
}

static int dtr_post_tx_desc(struct drbd_rdma_stream *rdma_stream, struct drbd_rdma_tx_desc *tx_desc)
{
	struct ib_device *device = rdma_stream->cm.id->device;
	struct ib_send_wr send_wr, *send_wr_failed;
	long t;
	int err;

	t = wait_event_interruptible_timeout(rdma_stream->send_wq,
			atomic_read(&rdma_stream->tx_descs_posted) < rdma_stream->tx_descs_max,
			rdma_stream->send_timeout);

	if (t <= 0)
		return t == 0 ? -EAGAIN : -EINTR;

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
		pr_err("%s: ib_post_send failed\n", rdma_stream->name);
		atomic_dec(&rdma_stream->tx_descs_posted);

		return err;
	}

	// pr_info("%s: Created send_wr (%p, %p): lkey=%x, addr=%llx, length=%d\n", rdma_stream->name, tx_desc->page, tx_desc, tx_desc->sge.lkey, tx_desc->sge.addr, tx_desc->sge.length);

	return 0;
}

/* allocate rdma specific resources for the stream */
static int dtr_alloc_rdma_resources(struct drbd_rdma_stream *rdma_stream, struct drbd_connection *connection)
{
	struct net_conf *nc;
	int err;
	int rcvbuf_size = RDMA_DEF_BUFFER_SIZE;
	int sndbuf_size = RDMA_DEF_BUFFER_SIZE;

	rcu_read_lock();
	nc = rcu_dereference(connection->net_conf);
	if (nc) {
		if (nc->rcvbuf_size)
			rcvbuf_size = nc->rcvbuf_size;
		if (nc->sndbuf_size)
			sndbuf_size = nc->sndbuf_size;
	}
	rcu_read_unlock();

	rdma_stream->tx_descs_max = sndbuf_size / DRBD_SOCKET_BUFFER_SIZE;
	rdma_stream->rx_descs_max = rcvbuf_size / DRBD_SOCKET_BUFFER_SIZE;

	rdma_stream->rx_descs_want_posted = rdma_stream->rx_descs_max / 2;

	rdma_stream->current_rx.desc = NULL;
	rdma_stream->current_rx.pos = NULL;
	rdma_stream->current_rx.bytes_left = 0;

	rdma_stream->recv_timeout = MAX_SCHEDULE_TIMEOUT;
	rdma_stream->send_timeout = MAX_SCHEDULE_TIMEOUT;

	sprintf(rdma_stream->name, "s%06d", stream_nr++);
	rdma_stream->rx_allocation_size = DRBD_SOCKET_BUFFER_SIZE; /* 4096 usually PAGE_SIZE */

	init_waitqueue_head(&rdma_stream->recv_wq);
	init_waitqueue_head(&rdma_stream->send_wq);
	rdma_stream->rdma_transport =
		container_of(connection->transport, struct drbd_rdma_transport, transport);

	// pr_info("creating stream: %s\n", rdma_stream->name);

	/* alloc protection domain (PD) */
	rdma_stream->pd = ib_alloc_pd(rdma_stream->cm.id->device);
	if (IS_ERR(rdma_stream->pd)) {
		pr_err("ib_alloc_pd failed\n");
		err = PTR_ERR(rdma_stream->pd);
		goto pd_failed;
	}

	/* create recv completion queue (CQ) */
	rdma_stream->recv_cq = ib_create_cq(rdma_stream->cm.id->device,
			dtr_rx_cq_event_handler, NULL, rdma_stream,
			rdma_stream->rx_descs_max, 0);
	if (IS_ERR(rdma_stream->recv_cq)) {
		pr_err("ib_create_cq recv failed\n");
		err = PTR_ERR(rdma_stream->recv_cq);
		goto recv_cq_failed;
	}

	/* create send completion queue (CQ) */
	rdma_stream->send_cq = ib_create_cq(rdma_stream->cm.id->device,
			dtr_tx_cq_event_handler, NULL, rdma_stream,
			rdma_stream->rx_descs_max, 0);
	if (IS_ERR(rdma_stream->send_cq)) {
		pr_err("ib_create_cq send failed\n");
		err = PTR_ERR(rdma_stream->send_cq);
		goto send_cq_failed;
	}

	/* arm CQs */
	err = ib_req_notify_cq(rdma_stream->recv_cq, IB_CQ_NEXT_COMP);
	if (err) {
		pr_err("ib_req_notify_cq recv failed\n");
		goto notify_failed;
	}

	err = ib_req_notify_cq(rdma_stream->send_cq, IB_CQ_NEXT_COMP);
	if (err) {
		pr_err(" ib_req_notify_cq send failed\n");
		goto notify_failed;
	}

	/* create a queue pair (QP) */
	err = dtr_create_qp(rdma_stream);
	if (err) {
		pr_err(" create_qp error %d\n", err);
		goto createqp_failed;
	}

	/* create RDMA memory region (MR) */
	rdma_stream->dma_mr = ib_get_dma_mr(rdma_stream->pd,
			IB_ACCESS_LOCAL_WRITE |
			IB_ACCESS_REMOTE_READ |
			IB_ACCESS_REMOTE_WRITE);
	if (IS_ERR(rdma_stream->dma_mr)) {
		pr_err(" ib_get_dma_mr failed\n");
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

static void dtr_drain_cq(struct ib_cq *cq)
{
	struct ib_wc wc;

	while(ib_poll_cq(cq, 1, &wc) == 1)
		;
}

static void dtr_disconnect_stream(struct drbd_rdma_stream *rdma_stream)
{
	if (!rdma_stream || !rdma_stream->cm.id)
		return;

	rdma_disconnect(rdma_stream->cm.id);
	/* We are ignoring errors here on purpose */

	if (rdma_stream->send_cq)
		dtr_drain_cq(rdma_stream->send_cq);

	if (rdma_stream->recv_cq)
		dtr_drain_cq(rdma_stream->recv_cq);

	wait_event_interruptible_timeout(rdma_stream->cm.state_wq,
					 rdma_stream->cm.state >= DISCONNECTED,
					 HZ);

	if (rdma_stream->cm.state < DISCONNECTED)
		pr_warn("%s: WARN: not properly disconnected\n", rdma_stream->name);
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

	// pr_info("%s: dtr_free_stream() %p\n", rdma_stream->name, rdma_stream);
	rdma_stream->name[0] = 'X';
	rdma_stream->name[1] = 'X';

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
		drbd_err(connection, "rdma_create_id() failed %d\n", err);
		goto out;
	}
	strcpy(rdma_stream->cm.name, "new");

	err = rdma_resolve_addr(rdma_stream->cm.id, NULL, (struct sockaddr *)&connection->peer_addr, 2000);
	if (err) {
		drbd_err(connection, "rdma_resolve_addr error %d\n", err);
		goto out;
	}

	wait_event_interruptible(rdma_stream->cm.state_wq,
				 rdma_stream->cm.state >= ROUTE_RESOLVED);

	if (rdma_stream->cm.state != ROUTE_RESOLVED)
		goto out; /* Happens if peer not reachable */

	err = dtr_alloc_rdma_resources(rdma_stream, connection);
	if (err) {
		drbd_err(connection, "failed allocating resources %d\n", err);
		goto out;
	}
	strcpy(rdma_stream->cm.name, rdma_stream->name);

	/* Connect peer */
	memset(&conn_param, 0, sizeof conn_param);
	conn_param.responder_resources = 1;
	conn_param.initiator_depth = 1;
	conn_param.retry_count = 10;

	err = rdma_connect(rdma_stream->cm.id, &conn_param);
	if (err) {
		drbd_err(connection, "rdma_connect error %d\n", err);
		goto out;
	}

	/* Make sure that we see an eventuall RDMA_CM_EVENT_REJECTED here (cm.state
	   is ERROR in that case). We can not wait for RDMA_CM_EVENT_ESTABLISHED since
	   that requires the peer to call accept.
	   -> would lead to distributed deadlock. */
	wait_event_interruptible_timeout(rdma_stream->cm.state_wq,
					 rdma_stream->cm.state != ROUTE_RESOLVED,
					 HZ/20);

	if (rdma_stream->cm.state == ERROR)
		goto out;

	// pr_info("%s: rdma_connect successful\n", rdma_stream->name);
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
		drbd_err(connection, "rdma_create_id() failed\n");
		goto out;
	}
	strcpy(listener->cm.name, "listen");

	err = rdma_bind_addr(listener->cm.id, (struct sockaddr *) &connection->my_addr);
	if (err) {
		drbd_err(connection, "rdma_bind_addr error %d\n", err);
		goto out;
	}

	err = rdma_listen(listener->cm.id, 3);
	if (err) {
		drbd_err(connection, "rdma_listen error %d\n", err);
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
	rv = waiter->waiter.listener->pending_accepts > 0 || waiter->rdma_stream != NULL;
	spin_unlock_bh(&resource->listeners_lock);

	return rv;
}

static int dtr_wait_for_connect(struct dtr_waiter *waiter, struct drbd_rdma_stream **ret_rdma_stream)
{
	struct drbd_connection *connection = waiter->waiter.connection;
	struct drbd_resource *resource = connection->resource;
	struct drbd_rdma_stream *rdma_stream = NULL;
	struct sockaddr_storage *peer_addr;
	struct net_conf *nc;
	struct dtr_listener *listener =
		container_of(waiter->waiter.listener, struct dtr_listener, listener);
	struct rdma_conn_param conn_param;
	struct rdma_cm_id *cm_id = NULL;
	struct drbd_waiter *waiter2_gen;
	long timeo;
	int connect_int, err = 0;

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

retry:
	dtr_free_stream(rdma_stream);
	rdma_stream = NULL;

	timeo = wait_event_interruptible_timeout(waiter->waiter.wait, dtr_wait_connect_cond(waiter), timeo);
	if (timeo <= 0)
		return -EAGAIN;

	spin_lock_bh(&resource->listeners_lock);
	if (waiter->rdma_stream) {
		rdma_stream = waiter->rdma_stream;
		waiter->rdma_stream = NULL;
	} else if (listener->listener.pending_accepts > 0) {
		listener->listener.pending_accepts--;

		cm_id = listener->child_cms; /* Get head from single linked list */
		listener->child_cms = cm_id->context;
		cm_id->context = NULL;
	}
	spin_unlock_bh(&resource->listeners_lock);

	if (cm_id) {
		rdma_stream = kzalloc(sizeof(*rdma_stream), GFP_KERNEL);
		if (!rdma_stream)
			return -ENOMEM;

		rdma_stream->cm.state = IDLE;
		init_waitqueue_head(&rdma_stream->cm.state_wq);
		cm_id->context = &rdma_stream->cm;
		rdma_stream->cm.id = cm_id;

		err = dtr_alloc_rdma_resources(rdma_stream, connection);
		if (err) {
			drbd_err(connection, "failed allocating stream resources %d\n", err);
			goto err;
		}
		strcpy(rdma_stream->cm.name, rdma_stream->name);

		memset(&conn_param, 0, sizeof conn_param);
		conn_param.responder_resources = 1;
		conn_param.initiator_depth = 1;

		err = rdma_accept(rdma_stream->cm.id, &conn_param);
		if (err) {
			drbd_err(connection, "rdma_accept error %d\n", err);
			goto err;
		}

		peer_addr = &cm_id->route.addr.dst_addr;

		spin_lock_bh(&resource->listeners_lock);
		waiter2_gen = drbd_find_waiter_by_addr(waiter->waiter.listener, peer_addr);

		if (waiter2_gen && waiter2_gen != &waiter->waiter) {
			struct dtr_waiter *waiter2 =
				container_of(waiter2_gen, struct dtr_waiter, waiter);

			if (waiter2->rdma_stream) {
				drbd_err(waiter2->waiter.connection,
					 "Receiver busy; rejecting incoming connection\n");
				goto retry_locked;
			}
			/* pass it to the right waiter... */
			waiter2->rdma_stream = rdma_stream;
			rdma_stream = NULL;
			wake_up(&waiter2->waiter.wait);
			goto retry_locked;
		}
		spin_unlock_bh(&resource->listeners_lock);

		if (!waiter2_gen) {
			struct sockaddr_in *from_sin, *to_sin;

			from_sin = (struct sockaddr_in *)&peer_addr;
			to_sin = (struct sockaddr_in *)&connection->my_addr;
			drbd_err(resource, "Closing unexpected connection from "
				 "%pI4 to port %u\n",
				 &from_sin->sin_addr,
				 be16_to_cpu(to_sin->sin_port));

			goto retry;
		}

		/* if waiter2_gen is not null and rdma_stream is also not null,
		   we know the connection is for us... return it with RC = success */
	}

	*ret_rdma_stream = rdma_stream;
	return 0;

err:
	dtr_free_stream(rdma_stream);
	return err;

retry_locked:
	spin_unlock_bh(&resource->listeners_lock);
	goto retry;
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
	waiter.rdma_stream = NULL;

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

	data_stream->send_timeout = timeout;
	control_stream->send_timeout = timeout;

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

	// pr_info("%s: in send_page, size: %zu\n", rdma_stream->name, size);

	if (rdma_stream->cm.state > CONNECTED)
		return -ECONNRESET;

	tx_desc = kmalloc(sizeof(*tx_desc), GFP_NOIO);
	if (!tx_desc)
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
