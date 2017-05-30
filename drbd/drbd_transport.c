#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt

#include <linux/spinlock.h>
#include <linux/module.h>
#include <net/ipv6.h>
#include <drbd_transport.h>
#include <drbd_int.h>

static LIST_HEAD(transport_classes);
static DECLARE_RWSEM(transport_classes_lock);

static struct drbd_transport_class *__find_transport_class(const char *transport_name)
{
	struct drbd_transport_class *transport_class;

	list_for_each_entry(transport_class, &transport_classes, list)
		if (!strcmp(transport_class->name, transport_name))
			return transport_class;

	return NULL;
}

int drbd_register_transport_class(struct drbd_transport_class *transport_class, int version,
				  int drbd_transport_size)
{
	int rv = 0;
	if (version != DRBD_TRANSPORT_API_VERSION) {
		pr_err("DRBD_TRANSPORT_API_VERSION not compatible\n");
		return -EINVAL;
	}

	if (drbd_transport_size != sizeof(struct drbd_transport)) {
		pr_err("sizeof(drbd_transport) not compatible\n");
		return -EINVAL;
	}

	down_write(&transport_classes_lock);
	if (__find_transport_class(transport_class->name)) {
		pr_err("transport class '%s' already registered\n", transport_class->name);
		rv = -EEXIST;
	} else
		list_add_tail(&transport_class->list, &transport_classes);
	up_write(&transport_classes_lock);
	return rv;
}

void drbd_unregister_transport_class(struct drbd_transport_class *transport_class)
{
	down_write(&transport_classes_lock);
	if (!__find_transport_class(transport_class->name)) {
		pr_crit("unregistering unknown transport class '%s'\n",
			transport_class->name);
		BUG();
	}
	list_del_init(&transport_class->list);
	up_write(&transport_classes_lock);
}

static struct drbd_transport_class *get_transport_class(const char *name)
{
	struct drbd_transport_class *tc;

	down_read(&transport_classes_lock);
	tc = __find_transport_class(name);
	if (tc && !try_module_get(tc->module))
		tc = NULL;
	up_read(&transport_classes_lock);
	return tc;
}

struct drbd_transport_class *drbd_get_transport_class(const char *name)
{
	struct drbd_transport_class *tc = get_transport_class(name);

	if (!tc) {
		request_module("drbd_transport_%s", name);
		tc = get_transport_class(name);
	}

	return tc;
}

void drbd_put_transport_class(struct drbd_transport_class *tc)
{
	/* convenient in the error cleanup path */
	if (!tc)
		return;
	down_read(&transport_classes_lock);
	module_put(tc->module);
	up_read(&transport_classes_lock);
}

void drbd_print_transports_loaded(struct seq_file *seq)
{
	struct drbd_transport_class *tc;

	down_read(&transport_classes_lock);

	seq_puts(seq, "Transports (api:" __stringify(DRBD_TRANSPORT_API_VERSION) "):");
	list_for_each_entry(tc, &transport_classes, list) {
		seq_printf(seq, " %s (%s)", tc->name,
				tc->module->version ? tc->module->version : "NONE");
	}
	seq_putc(seq, '\n');

	up_read(&transport_classes_lock);
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

static bool addr_and_port_equal(const struct sockaddr_storage *addr1, const struct sockaddr_storage *addr2)
{
	if (!addr_equal(addr1, addr2))
		return false;

	if (addr1->ss_family == AF_INET6) {
		const struct sockaddr_in6 *v6a1 = (const struct sockaddr_in6 *)addr1;
		const struct sockaddr_in6 *v6a2 = (const struct sockaddr_in6 *)addr2;

		return v6a1->sin6_port == v6a2->sin6_port;
	} else /* AF_INET, AF_SSOCKS, AF_SDP */ {
		const struct sockaddr_in *v4a1 = (const struct sockaddr_in *)addr1;
		const struct sockaddr_in *v4a2 = (const struct sockaddr_in *)addr2;

		return v4a1->sin_port == v4a2->sin_port;
	}

	return false;
}

static struct drbd_listener *find_listener(struct drbd_connection *connection,
					   const struct sockaddr_storage *addr)
{
	struct drbd_resource *resource = connection->resource;
	struct drbd_listener *listener;

	list_for_each_entry(listener, &resource->listeners, list) {
		if (addr_and_port_equal(&listener->listen_addr, addr)) {
			kref_get(&listener->kref);
			return listener;
		}
	}
	return NULL;
}

int drbd_get_listener(struct drbd_transport *transport, struct drbd_path *path,
		      int (*init_listener)(struct drbd_transport *, const struct sockaddr *addr, struct drbd_listener *))
{
	struct drbd_connection *connection =
		container_of(transport, struct drbd_connection, transport);
	struct sockaddr *addr = (struct sockaddr *)&path->my_addr;
	struct drbd_resource *resource = connection->resource;
	struct drbd_listener *listener, *new_listener = NULL;
	int err, tries = 0;

	while (1) {
		spin_lock_bh(&resource->listeners_lock);
		listener = find_listener(connection, (struct sockaddr_storage *)addr);
		if (!listener && new_listener) {
			list_add(&new_listener->list, &resource->listeners);
			listener = new_listener;
			new_listener = NULL;
		}
		if (listener) {
			list_add(&path->listener_link, &listener->waiters);
			path->listener = listener;
		}
		spin_unlock_bh(&resource->listeners_lock);

		if (new_listener)
			new_listener->destroy(new_listener);

		if (listener)
			return 0;

		new_listener = kmalloc(transport->class->listener_instance_size, GFP_KERNEL);
		if (!new_listener)
			return -ENOMEM;

		kref_init(&new_listener->kref);
		INIT_LIST_HEAD(&new_listener->waiters);
		new_listener->resource = resource;
		new_listener->pending_accepts = 0;
		spin_lock_init(&new_listener->waiters_lock);

		err = init_listener(transport, addr, new_listener);
		if (err) {
			kfree(new_listener);
			new_listener = NULL;
			if (err == -EADDRINUSE && ++tries < 3) {
				schedule_timeout_uninterruptible(HZ / 20);
				continue;
			}
			return err;
		}
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

void drbd_put_listener(struct drbd_path *path)
{
	struct drbd_resource *resource;
	struct drbd_listener *listener;

	listener = xchg(&path->listener, NULL);
	if (!listener)
		return;

	resource = listener->resource;
	spin_lock_bh(&resource->listeners_lock);
	list_del(&path->listener_link);
	spin_unlock_bh(&resource->listeners_lock);
	kref_put(&listener->kref, drbd_listener_destroy);
}

struct drbd_path *drbd_find_path_by_addr(struct drbd_listener *listener, struct sockaddr_storage *addr)
{
	struct drbd_path *path;

	list_for_each_entry(path, &listener->waiters, listener_link) {
		if (addr_equal(&path->peer_addr, addr))
			return path;
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
bool drbd_stream_send_timed_out(struct drbd_transport *transport, enum drbd_stream stream)
{
	struct drbd_connection *connection =
		container_of(transport, struct drbd_connection, transport);
	bool drop_it;

	drop_it = stream == CONTROL_STREAM
		|| !connection->ack_receiver.task
		|| get_t_state(&connection->ack_receiver) != RUNNING
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

bool drbd_should_abort_listening(struct drbd_transport *transport)
{
	struct drbd_connection *connection =
		container_of(transport, struct drbd_connection, transport);
	bool abort = false;

	if (connection->cstate[NOW] <= C_DISCONNECTING)
		abort = true;
	if (signal_pending(current)) {
		flush_signals(current);
		smp_rmb();
		if (get_t_state(&connection->receiver) == EXITING)
			abort = true;
	}

	return abort;
}

/* Called by a transport if a path was established / disconnected */
void drbd_path_event(struct drbd_transport *transport, struct drbd_path *path)
{
	struct drbd_connection *connection =
		container_of(transport, struct drbd_connection, transport);

	notify_path(connection, path, NOTIFY_CHANGE);
}

/* Network transport abstractions */
EXPORT_SYMBOL_GPL(drbd_register_transport_class);
EXPORT_SYMBOL_GPL(drbd_unregister_transport_class);
EXPORT_SYMBOL_GPL(drbd_get_listener);
EXPORT_SYMBOL_GPL(drbd_put_listener);
EXPORT_SYMBOL_GPL(drbd_find_path_by_addr);
EXPORT_SYMBOL_GPL(drbd_stream_send_timed_out);
EXPORT_SYMBOL_GPL(drbd_should_abort_listening);
EXPORT_SYMBOL_GPL(drbd_path_event);
