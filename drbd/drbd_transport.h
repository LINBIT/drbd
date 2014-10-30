#ifndef DRBD_TRANSPORT_H
#define DRBD_TRANSPORT_H

#include <linux/kref.h>
#include <linux/list.h>
#include <linux/wait.h>
#include <linux/socket.h>


struct drbd_resource;
struct drbd_connection;
struct drbd_peer_device;

enum drbd_stream {
	DATA_STREAM,
	CONTROL_STREAM
};

enum drbd_tr_hints {
	CORK,
	UNCORK,
	NODELAY,
	NOSPACE,
	QUICKACK
};

enum { /* bits in the flags word */
	NET_CONGESTED,		/* The data socket is congested */
	RESOLVE_CONFLICTS,	/* Set on one node, cleared on the peer! */
};

/* Each transport implementation should embed a struct drbd_transport
   into it's instance data structure.
   The transport implementation should only access the connection
   only for reading (connection config, etc...) */
struct drbd_transport {
	struct drbd_transport_ops *ops;
	struct drbd_connection *connection;

	/* These members are intended to be updated by the transport: */
	unsigned int ko_count;
	unsigned long flags;
};

struct drbd_transport_stats {
	int unread_received;
	int unacked_send;
	int send_buffer_size;
	int send_buffer_used;
};

struct drbd_transport_ops {
	void (*free)(struct drbd_transport *, bool put_transport);
	int (*connect)(struct drbd_transport *);
	int (*send)(struct drbd_transport *, enum drbd_stream, void *buf, size_t size, unsigned msg_flags);
	int (*recv)(struct drbd_transport *, enum drbd_stream, void *buf, size_t size, int flags);
	void (*stats)(struct drbd_transport *, struct drbd_transport_stats *stats);
	void (*set_rcvtimeo)(struct drbd_transport *, enum drbd_stream, long timeout);
	long (*get_rcvtimeo)(struct drbd_transport *, enum drbd_stream);
	int (*send_page)(struct drbd_transport *, struct drbd_peer_device *peer_device, struct page *page,
			int offset, size_t size, unsigned msg_flags);
	bool (*stream_ok)(struct drbd_transport *, enum drbd_stream);
	bool (*hint)(struct drbd_transport *, enum drbd_stream, enum drbd_tr_hints hint);
};

struct drbd_transport_class {
	const char *name;
	struct drbd_transport *(*create)(struct drbd_connection *);
	struct list_head list;
};


/* An "abstract base class" for transport implementations. I.e. it
   should be embedded into a transport specific representation of a
   listening "socket" */
struct drbd_listener {
	struct kref kref;
	struct drbd_resource *resource;
	struct list_head list; /* link for resource->listeners */
	struct list_head waiters; /* list head for waiter structs*/
	int pending_accepts;
	struct sockaddr_storage listen_addr;
	void (*destroy)(struct drbd_listener *);
};

/* This represents a drbd receiver thread that is waiting for an
   incoming connection attempt. Again, should be embedded into a
   implementation object */
struct drbd_waiter {
	struct drbd_connection *connection;
	wait_queue_head_t wait;
	struct list_head list;
	struct drbd_listener *listener;
};

extern int drbd_register_transport_class(struct drbd_transport_class *transport_class);
extern void drbd_unregister_transport_class(struct drbd_transport_class *transport_class);
extern struct drbd_transport *drbd_create_transport(const char *name, struct drbd_connection *);

extern int drbd_get_listener(struct drbd_waiter *waiter,
			     struct drbd_listener * (*create_fn)(struct drbd_connection *));
extern void drbd_put_listener(struct drbd_waiter *waiter);
extern struct drbd_waiter *drbd_find_waiter_by_addr(struct drbd_listener *, struct sockaddr_storage *);

#endif
