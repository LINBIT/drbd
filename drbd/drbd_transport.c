#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt

#include <linux/spinlock.h>
#include <linux/module.h>
#include <net/ipv6.h>
#include <drbd_transport.h>
#include <drbd_int.h>

static LIST_HEAD(transport_classes);
static spinlock_t transport_classes_lock = __SPIN_LOCK_UNLOCKED(&transport_classes_lock);

int drbd_register_transport_class(struct drbd_transport_class *transport_class, int version,
				  int drbd_transport_size)
{
	if (version != DRBD_TRANSPORT_API_VERSION) {
		pr_err("DRBD_TRANSPORT_API_VERSION not compatible\n");
		return -EINVAL;
	}

	if (drbd_transport_size != sizeof(struct drbd_transport)) {
		pr_err("sizeof(drbd_transport) not compatible\n");
		return -EINVAL;
	}

	spin_lock(&transport_classes_lock);
	list_add_tail(&transport_class->list, &transport_classes);
	spin_unlock(&transport_classes_lock);

	return 0;
}

void drbd_unregister_transport_class(struct drbd_transport_class *transport_class)
{
	spin_lock(&transport_classes_lock);
	list_del_init(&transport_class->list);
	spin_unlock(&transport_classes_lock);
}

static struct drbd_transport_class *__find_transport_class(const char *transport_name)
{
	struct drbd_transport_class *transport_class;

	spin_lock(&transport_classes_lock);
	list_for_each_entry(transport_class, &transport_classes, list) {
		if (!strcmp(transport_class->name, transport_name))
			goto found;
	}
	transport_class = NULL;
found:
	spin_unlock(&transport_classes_lock);
	return transport_class;
}

struct drbd_transport_class *
drbd_find_transport_class(const char *transport_name)
{
	struct drbd_transport_class *transport_class;

	transport_class = __find_transport_class(transport_name);
	if (!transport_class) {
		int err = request_module("drbd_transport_%s", transport_name);

		if (!err)
			transport_class = __find_transport_class(transport_name);
		else
			pr_warn("cannot load drbd_transport_%s kernel module\n", transport_name);
	}

	return transport_class;
}


static bool addr_equal(const struct sockaddr_storage *addr1, const struct sockaddr_storage *addr2)
{
	if (addr1->ss_family != addr2->ss_family)
		return false;

	if (addr1->ss_family == AF_INET6) {
		const struct sockaddr_in6 *v6a1 = (const struct sockaddr_in6 *)addr1;
		const struct sockaddr_in6 *v6a2 = (const struct sockaddr_in6 *)addr2;

		if (!ipv6_addr_equal(&v6a1->sin6_addr, &v6a2->sin6_addr))
			return false;
		else if (ipv6_addr_type(&v6a1->sin6_addr) & IPV6_ADDR_LINKLOCAL)
			return v6a1->sin6_scope_id == v6a2->sin6_scope_id;
		return true;
	} else /* AF_INET, AF_SSOCKS, AF_SDP */ {
		const struct sockaddr_in *v4a1 = (const struct sockaddr_in *)addr1;
		const struct sockaddr_in *v4a2 = (const struct sockaddr_in *)addr2;

		return v4a1->sin_addr.s_addr == v4a2->sin_addr.s_addr;
	}
}

static struct drbd_listener *find_listener(struct drbd_connection *connection)
{
	struct drbd_resource *resource = connection->resource;
	struct drbd_listener *listener;

	list_for_each_entry(listener, &resource->listeners, list) {
		if (addr_equal(&listener->listen_addr, &connection->transport.my_addr)) {
			kref_get(&listener->kref);
			return listener;
		}
	}
	return NULL;
}

int drbd_get_listener(struct drbd_waiter *waiter,
		      int (*create_listener)(struct drbd_transport *, struct drbd_listener **))
{
	struct drbd_connection *connection = waiter->connection;
	struct drbd_resource *resource = connection->resource;
	struct drbd_listener *listener, *new_listener = NULL;
	int err;

	init_waitqueue_head(&waiter->wait);

	while (1) {
		spin_lock_bh(&resource->listeners_lock);
		listener = find_listener(connection);
		if (!listener && new_listener) {
			list_add(&new_listener->list, &resource->listeners);
			listener = new_listener;
			new_listener = NULL;
		}
		if (listener) {
			list_add(&waiter->list, &listener->waiters);
			waiter->listener = listener;
		}
		spin_unlock_bh(&resource->listeners_lock);

		if (new_listener)
			new_listener->destroy(new_listener);

		if (listener)
			return 0;

		err = create_listener(&waiter->connection->transport, &new_listener);
		if (err)
			return err;

		kref_init(&new_listener->kref);
		INIT_LIST_HEAD(&new_listener->waiters);
		new_listener->resource = resource;
		new_listener->pending_accepts = 0;
		spin_lock_init(&new_listener->waiters_lock);
	}
}

static void drbd_listener_destroy(struct kref *kref)
{
	struct drbd_listener *listener = container_of(kref, struct drbd_listener, kref);
	struct drbd_resource *resource = listener->resource;

	spin_lock_bh(&resource->listeners_lock);
	list_del(&listener->list);
	spin_unlock_bh(&resource->listeners_lock);

	listener->destroy(listener);
}

void drbd_put_listener(struct drbd_waiter *waiter)
{
	struct drbd_resource *resource;

	if (!waiter->listener)
		return;

	resource = waiter->listener->resource;
	spin_lock_bh(&resource->listeners_lock);
	list_del(&waiter->list);
	if (!list_empty(&waiter->listener->waiters) && waiter->listener->pending_accepts) {
		/* This receiver no longer does accept wake ups. In case we got woken up to do
		   one, and there are more receivers, wake one of the other guys to do it */
		struct drbd_waiter *ad2;

		ad2 = list_entry(waiter->listener->waiters.next, struct drbd_waiter, list);
		wake_up(&ad2->wait);
	}
	spin_unlock_bh(&resource->listeners_lock);
	kref_put(&waiter->listener->kref, drbd_listener_destroy);
	waiter->listener = NULL;
}

struct drbd_waiter *drbd_find_waiter_by_addr(struct drbd_listener *listener, struct sockaddr_storage *addr)
{
	struct drbd_waiter *waiter;

	list_for_each_entry(waiter, &listener->waiters, list) {
		if (addr_equal(&waiter->connection->transport.peer_addr, addr))
			return waiter;
	}

	return NULL;
}

/**
 * drbd_stream_send_timed_out() - Tells transport if the connection should stay alive
 * @connection:	DRBD connection to operate on.
 * @stream:     DATA_STREAM or CONTROL_STREAM
 *
 * When it returns true, the transport should return -EAGAIN to its caller of the
 * send function. When it returns false the transport should keep on trying to
 * get the packet through.
 */
bool drbd_stream_send_timed_out(struct drbd_connection *connection, enum drbd_stream stream)
{
	bool drop_it;

	drop_it = stream == CONTROL_STREAM
		|| !connection->asender.task
		|| get_t_state(&connection->asender) != RUNNING
		|| connection->cstate[NOW] < C_CONNECTED;

	if (drop_it)
		return true;

	drop_it = !--connection->transport.ko_count;
	if (!drop_it) {
		drbd_err(connection, "[%s/%d] sending time expired, ko = %u\n",
			 current->comm, current->pid, connection->transport.ko_count);
		request_ping(connection);
	}

	return drop_it;

}

/* Network transport abstractions */
EXPORT_SYMBOL_GPL(drbd_register_transport_class);
EXPORT_SYMBOL_GPL(drbd_unregister_transport_class);
EXPORT_SYMBOL_GPL(drbd_get_listener);
EXPORT_SYMBOL_GPL(drbd_put_listener);
EXPORT_SYMBOL_GPL(drbd_find_waiter_by_addr);
EXPORT_SYMBOL_GPL(drbd_stream_send_timed_out);
