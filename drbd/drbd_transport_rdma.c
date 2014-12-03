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


MODULE_AUTHOR("Roland Kammerer <roland.kammerer@linbit.com>");
MODULE_DESCRIPTION("RDMA transport layer for DRBD");
MODULE_LICENSE("GPL");


struct drbd_rdma_transport {
	struct drbd_transport transport;
	/* xxx */
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

	return 0;
}

static int dtr_recv(struct drbd_transport *transport, enum drbd_stream stream, void *buf, size_t size, int flags)
{
	struct drbd_rdma_transport *rdma_transport =
		container_of(transport, struct drbd_rdma_transport, transport);

	return 0;
}

static void dtr_stats(struct drbd_transport* transport, struct drbd_transport_stats *stats)
{
}

static int dtr_connect(struct drbd_transport *transport)
{
	struct drbd_rdma_transport *rdma_transport =
		container_of(transport, struct drbd_rdma_transport, transport);

	return 0;
}

static void dtr_set_rcvtimeo(struct drbd_transport *transport, enum drbd_stream stream, long timeout)
{
}

static long dtr_get_rcvtimeo(struct drbd_transport *transport, enum drbd_stream stream)
{
	return 0;
}

static bool dtr_stream_ok(struct drbd_transport *transport, enum drbd_stream stream)
{
	return true;
}

static int dtr_send_page(struct drbd_transport *transport, enum drbd_stream stream,
			 struct page *page, int offset, size_t size, unsigned msg_flags)
{
	return 0;
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
	return drbd_register_transport_class(&rdma_transport_class);
}

static void __exit dtr_cleanup(void)
{
	drbd_unregister_transport_class(&rdma_transport_class);
}

module_init(dtr_init)
module_exit(dtr_cleanup)
