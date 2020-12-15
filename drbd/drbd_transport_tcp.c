// SPDX-License-Identifier: GPL-2.0-or-later
/*
   drbd_transport_tcp.c

   This file is part of DRBD.

   Copyright (C) 2014-2017, LINBIT HA-Solutions GmbH.


*/

#include <linux/module.h>
#include <linux/errno.h>
#include <linux/socket.h>
#include <linux/pkt_sched.h>
#include <linux/sched/signal.h>
#include <linux/net.h>
#include <linux/tcp.h>
#include <linux/highmem.h>
#include <linux/drbd_genl_api.h>
#include <linux/drbd_config.h>
#include <drbd_protocol.h>
#include <drbd_transport.h>
#include "drbd_wrappers.h"


MODULE_AUTHOR("Philipp Reisner <philipp.reisner@linbit.com>");
MODULE_AUTHOR("Lars Ellenberg <lars.ellenberg@linbit.com>");
MODULE_AUTHOR("Roland Kammerer <roland.kammerer@linbit.com>");
MODULE_DESCRIPTION("TCP (SDP, SSOCKS) transport layer for DRBD");
MODULE_LICENSE("GPL");
MODULE_VERSION(REL_VERSION);

struct buffer {
	void *base;
	void *pos;
};

#define DTT_CONNECTING 1

struct drbd_tcp_transport {
	struct drbd_transport transport; /* Must be first! */
	spinlock_t paths_lock;
	unsigned long flags;
	struct socket *stream[2];
	struct buffer rbuf[2];
};

struct dtt_listener {
	struct drbd_listener listener;
	void (*original_sk_state_change)(struct sock *sk);
	struct socket *s_listen;

	wait_queue_head_t wait; /* woken if a connection came in */
};

/* Since each path might have a different local IP address, each
   path might need its own listener. Therefore the drbd_waiter object
   is embedded into the dtt_path and _not_ the dtt_waiter. */

struct dtt_socket_container {
	struct list_head list;
	struct socket *socket;
};

struct dtt_path {
	struct drbd_path path;

	struct list_head sockets; /* sockets passed to me by other receiver threads */
};

static int dtt_init(struct drbd_transport *transport);
static void dtt_free(struct drbd_transport *transport, enum drbd_tr_free_op free_op);
static int dtt_connect(struct drbd_transport *transport);
static int dtt_recv(struct drbd_transport *transport, enum drbd_stream stream, void **buf, size_t size, int flags);
static int dtt_recv_pages(struct drbd_transport *transport, struct drbd_page_chain_head *chain, size_t size);
static void dtt_stats(struct drbd_transport *transport, struct drbd_transport_stats *stats);
static void dtt_set_rcvtimeo(struct drbd_transport *transport, enum drbd_stream stream, long timeout);
static long dtt_get_rcvtimeo(struct drbd_transport *transport, enum drbd_stream stream);
static int dtt_send_page(struct drbd_transport *transport, enum drbd_stream, struct page *page,
		int offset, size_t size, unsigned msg_flags);
static int dtt_send_zc_bio(struct drbd_transport *, struct bio *bio);
static bool dtt_stream_ok(struct drbd_transport *transport, enum drbd_stream stream);
static bool dtt_hint(struct drbd_transport *transport, enum drbd_stream stream, enum drbd_tr_hints hint);
static void dtt_debugfs_show(struct drbd_transport *transport, struct seq_file *m);
static void dtt_update_congested(struct drbd_tcp_transport *tcp_transport);
static int dtt_add_path(struct drbd_transport *, struct drbd_path *path);
static int dtt_remove_path(struct drbd_transport *, struct drbd_path *);

static struct drbd_transport_class tcp_transport_class = {
	.name = "tcp",
	.instance_size = sizeof(struct drbd_tcp_transport),
	.path_instance_size = sizeof(struct dtt_path),
	.listener_instance_size = sizeof(struct dtt_listener),
	.module = THIS_MODULE,
	.init = dtt_init,
	.list = LIST_HEAD_INIT(tcp_transport_class.list),
};

static struct drbd_transport_ops dtt_ops = {
	.free = dtt_free,
	.connect = dtt_connect,
	.recv = dtt_recv,
	.recv_pages = dtt_recv_pages,
	.stats = dtt_stats,
	.set_rcvtimeo = dtt_set_rcvtimeo,
	.get_rcvtimeo = dtt_get_rcvtimeo,
	.send_page = dtt_send_page,
	.send_zc_bio = dtt_send_zc_bio,
	.stream_ok = dtt_stream_ok,
	.hint = dtt_hint,
	.debugfs_show = dtt_debugfs_show,
	.add_path = dtt_add_path,
	.remove_path = dtt_remove_path,
};

/* Might restart iteration, if current element is removed from list!! */
#define for_each_path_ref(path, transport)			\
	for (path = __drbd_next_path_ref(NULL, transport);	\
	     path;						\
	     path = __drbd_next_path_ref(path, transport))

/* This is save as long you use list_del_init() everytime something is removed
   from the list. */
static struct drbd_path *__drbd_next_path_ref(struct drbd_path *drbd_path,
					      struct drbd_transport *transport)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);

	spin_lock(&tcp_transport->paths_lock);
	if (!drbd_path) {
		drbd_path = list_first_entry_or_null(&transport->paths, struct drbd_path, list);
	} else {
		bool in_list = !list_empty(&drbd_path->list);
		kref_put(&drbd_path->kref, drbd_destroy_path);
		if (in_list) {
			/* Element still on the list, ref count can not drop to zero! */
			if (list_is_last(&drbd_path->list, &transport->paths))
				drbd_path = NULL;
			else
				drbd_path = list_next_entry(drbd_path, list);
		} else {
			/* No longer on the list, element might be freed already, restart from the start */
			drbd_path = list_first_entry_or_null(&transport->paths, struct drbd_path, list);
		}
	}
	if (drbd_path)
		kref_get(&drbd_path->kref);
	spin_unlock(&tcp_transport->paths_lock);

	return drbd_path;
}

static int dtt_init(struct drbd_transport *transport)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);
	enum drbd_stream i;

	spin_lock_init(&tcp_transport->paths_lock);
	tcp_transport->transport.ops = &dtt_ops;
	tcp_transport->transport.class = &tcp_transport_class;
	for (i = DATA_STREAM; i <= CONTROL_STREAM ; i++) {
		void *buffer = (void *)__get_free_page(GFP_KERNEL);
		if (!buffer)
			goto fail;
		tcp_transport->rbuf[i].base = buffer;
		tcp_transport->rbuf[i].pos = buffer;
	}

	return 0;
fail:
	free_page((unsigned long)tcp_transport->rbuf[0].base);
	return -ENOMEM;
}

static void dtt_free_one_sock(struct socket *socket)
{
	if (socket) {
		synchronize_rcu();
		kernel_sock_shutdown(socket, SHUT_RDWR);
		sock_release(socket);
	}
}

static void dtt_free(struct drbd_transport *transport, enum drbd_tr_free_op free_op)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);
	enum drbd_stream i;
	struct drbd_path *drbd_path;
	/* free the socket specific stuff,
	 * mutexes are handled by caller */

	for (i = DATA_STREAM; i <= CONTROL_STREAM; i++) {
		if (tcp_transport->stream[i]) {
			dtt_free_one_sock(tcp_transport->stream[i]);
			tcp_transport->stream[i] = NULL;
		}
	}

	for_each_path_ref(drbd_path, transport) {
		bool was_established = drbd_path->established;
		drbd_path->established = false;
		if (was_established)
			drbd_path_event(transport, drbd_path);
	}

	if (free_op == DESTROY_TRANSPORT) {
		struct drbd_path *tmp;

		for (i = DATA_STREAM; i <= CONTROL_STREAM; i++) {
			free_page((unsigned long)tcp_transport->rbuf[i].base);
			tcp_transport->rbuf[i].base = NULL;
		}
		spin_lock(&tcp_transport->paths_lock);
		list_for_each_entry_safe(drbd_path, tmp, &transport->paths, list) {
			list_del_init(&drbd_path->list);
			kref_put(&drbd_path->kref, drbd_destroy_path);
		}
		spin_unlock(&tcp_transport->paths_lock);
	}
}

static int _dtt_send(struct drbd_tcp_transport *tcp_transport, struct socket *socket,
		      void *buf, size_t size, unsigned msg_flags)
{
	struct kvec iov;
	struct msghdr msg;
	int rv, sent = 0;

	/* THINK  if (signal_pending) return ... ? */

	iov.iov_base = buf;
	iov.iov_len  = size;

	msg.msg_name       = NULL;
	msg.msg_namelen    = 0;
	msg.msg_control    = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags      = msg_flags | MSG_NOSIGNAL;

	do {
		rv = kernel_sendmsg(socket, &msg, &iov, 1, iov.iov_len);
		if (rv == -EAGAIN) {
			struct drbd_transport *transport = &tcp_transport->transport;
			enum drbd_stream stream =
				tcp_transport->stream[DATA_STREAM] == socket ?
					DATA_STREAM : CONTROL_STREAM;

			if (drbd_stream_send_timed_out(transport, stream))
				break;
			else
				continue;
		}
		if (rv == -EINTR) {
			flush_signals(current);
			rv = 0;
		}
		if (rv < 0)
			break;
		sent += rv;
		iov.iov_base += rv;
		iov.iov_len  -= rv;
	} while (sent < size);

	if (rv <= 0)
		return rv;

	return sent;
}

static int dtt_recv_short(struct socket *socket, void *buf, size_t size, int flags)
{
	struct kvec iov = {
		.iov_base = buf,
		.iov_len = size,
	};
	struct msghdr msg = {
		.msg_flags = (flags ? flags : MSG_WAITALL | MSG_NOSIGNAL)
	};

	return kernel_recvmsg(socket, &msg, &iov, 1, size, msg.msg_flags);
}

static int dtt_recv(struct drbd_transport *transport, enum drbd_stream stream, void **buf, size_t size, int flags)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);
	struct socket *socket = tcp_transport->stream[stream];
	void *buffer;
	int rv;

	if (!socket)
		return -ENOTCONN;

	if (flags & CALLER_BUFFER) {
		buffer = *buf;
		rv = dtt_recv_short(socket, buffer, size, flags & ~CALLER_BUFFER);
	} else if (flags & GROW_BUFFER) {
		TR_ASSERT(transport, *buf == tcp_transport->rbuf[stream].base);
		buffer = tcp_transport->rbuf[stream].pos;
		TR_ASSERT(transport, (buffer - *buf) + size <= PAGE_SIZE);

		rv = dtt_recv_short(socket, buffer, size, flags & ~GROW_BUFFER);
	} else {
		buffer = tcp_transport->rbuf[stream].base;

		rv = dtt_recv_short(socket, buffer, size, flags);
		if (rv > 0)
			*buf = buffer;
	}

	if (rv > 0)
		tcp_transport->rbuf[stream].pos = buffer + rv;

	return rv;
}

static int dtt_recv_pages(struct drbd_transport *transport, struct drbd_page_chain_head *chain, size_t size)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);
	struct socket *socket = tcp_transport->stream[DATA_STREAM];
	struct page *page;
	int err;

	if (!socket)
		return -ENOTCONN;

	drbd_alloc_page_chain(transport, chain, DIV_ROUND_UP(size, PAGE_SIZE), GFP_TRY);
	page = chain->head;
	if (!page)
		return -ENOMEM;

	page_chain_for_each(page) {
		size_t len = min_t(int, size, PAGE_SIZE);
		void *data = kmap(page);
		err = dtt_recv_short(socket, data, len, 0);
		kunmap(page);
		set_page_chain_offset(page, 0);
		set_page_chain_size(page, len);
		if (err < 0)
			goto fail;
		size -= len;
	}
	return 0;
fail:
	drbd_free_page_chain(transport, chain, 0);
	return err;
}

static void dtt_stats(struct drbd_transport *transport, struct drbd_transport_stats *stats)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);

	struct socket *socket = tcp_transport->stream[DATA_STREAM];

	if (socket) {
		struct sock *sk = socket->sk;
		struct tcp_sock *tp = tcp_sk(sk);

		stats->unread_received = tp->rcv_nxt - tp->copied_seq;
		stats->unacked_send = tp->write_seq - tp->snd_una;
		stats->send_buffer_size = sk->sk_sndbuf;
		stats->send_buffer_used = sk->sk_wmem_queued;
	}
}

static void dtt_setbufsize(struct socket *socket, unsigned int snd,
			   unsigned int rcv)
{
	/* open coded SO_SNDBUF, SO_RCVBUF */
	if (snd) {
		socket->sk->sk_sndbuf = snd;
		socket->sk->sk_userlocks |= SOCK_SNDBUF_LOCK;
	}
	if (rcv) {
		socket->sk->sk_rcvbuf = rcv;
		socket->sk->sk_userlocks |= SOCK_RCVBUF_LOCK;
	}
}

static bool dtt_path_cmp_addr(struct dtt_path *path)
{
	struct drbd_path *drbd_path = &path->path;
	int addr_size;

	addr_size = min(drbd_path->my_addr_len, drbd_path->peer_addr_len);
	return memcmp(&drbd_path->my_addr, &drbd_path->peer_addr, addr_size) > 0;
}

static int dtt_try_connect(struct drbd_transport *transport, struct dtt_path *path, struct socket **ret_socket)
{
	const char *what;
	struct socket *socket;
	struct sockaddr_storage my_addr, peer_addr;
	struct net_conf *nc;
	int err;
	int sndbuf_size, rcvbuf_size, connect_int;

	rcu_read_lock();
	nc = rcu_dereference(transport->net_conf);
	if (!nc) {
		rcu_read_unlock();
		return -EIO;
	}
	sndbuf_size = nc->sndbuf_size;
	rcvbuf_size = nc->rcvbuf_size;
	connect_int = nc->connect_int;
	rcu_read_unlock();

	my_addr = path->path.my_addr;
	if (my_addr.ss_family == AF_INET6)
		((struct sockaddr_in6 *)&my_addr)->sin6_port = 0;
	else
		((struct sockaddr_in *)&my_addr)->sin_port = 0; /* AF_INET & AF_SCI */

	/* In some cases, the network stack can end up overwriting
	   peer_addr.ss_family, so use a copy here. */
	peer_addr = path->path.peer_addr;

	what = "sock_create_kern";
	err = sock_create_kern(&init_net, my_addr.ss_family, SOCK_STREAM, IPPROTO_TCP, &socket);
	if (err < 0) {
		socket = NULL;
		goto out;
	}

	socket->sk->sk_rcvtimeo =
	socket->sk->sk_sndtimeo = connect_int * HZ;
	dtt_setbufsize(socket, sndbuf_size, rcvbuf_size);

	/* explicitly bind to the configured IP as source IP
	*  for the outgoing connections.
	*  This is needed for multihomed hosts and to be
	*  able to use lo: interfaces for drbd.
	* Make sure to use 0 as port number, so linux selects
	*  a free one dynamically.
	*/
	what = "bind before connect";
	err = socket->ops->bind(socket, (struct sockaddr *) &my_addr, path->path.my_addr_len);
	if (err < 0)
		goto out;

	/* connect may fail, peer not yet available.
	 * stay C_CONNECTING, don't go Disconnecting! */
	what = "connect";
	err = socket->ops->connect(socket, (struct sockaddr *) &peer_addr,
				   path->path.peer_addr_len, 0);
	if (err < 0) {
		switch (err) {
		case -ETIMEDOUT:
		case -EINPROGRESS:
		case -EINTR:
		case -ERESTARTSYS:
		case -ECONNREFUSED:
		case -ECONNRESET:
		case -ENETUNREACH:
		case -EHOSTDOWN:
		case -EHOSTUNREACH:
			err = -EAGAIN;
			break;
		case -EINVAL:
			err = -EADDRNOTAVAIL;
			break;
		}
	}

out:
	if (err < 0) {
		if (socket)
			sock_release(socket);
		if (err != -EAGAIN && err != -EADDRNOTAVAIL)
			tr_err(transport, "%s failed, err = %d\n", what, err);
	} else {
		*ret_socket = socket;
	}

	return err;
}

static int dtt_send_first_packet(struct drbd_tcp_transport *tcp_transport, struct socket *socket,
			     enum drbd_packet cmd, enum drbd_stream stream)
{
	struct p_header80 h;
	int msg_flags = 0;
	int err;

	if (!socket)
		return -EIO;

	h.magic = cpu_to_be32(DRBD_MAGIC);
	h.command = cpu_to_be16(cmd);
	h.length = 0;

	err = _dtt_send(tcp_transport, socket, &h, sizeof(h), msg_flags);

	return err;
}

/**
 * dtt_socket_free() - Free the socket
 * @socket:	pointer to the pointer to the socket.
 */
static void dtt_socket_free(struct socket **socket)
{
	if (!*socket)
		return;

	kernel_sock_shutdown(*socket, SHUT_RDWR);
	sock_release(*socket);
	*socket = NULL;
}

/**
 * dtt_socket_ok_or_free() - Free the socket if its connection is not okay
 * @socket:	pointer to the pointer to the socket.
 */
static bool dtt_socket_ok_or_free(struct socket **socket)
{
	if (!*socket)
		return false;

	if ((*socket)->sk->sk_state == TCP_ESTABLISHED)
		return true;

	dtt_socket_free(socket);
	return false;
}

static bool dtt_connection_established(struct drbd_transport *transport,
				       struct socket **socket1,
				       struct socket **socket2,
				       struct dtt_path **first_path)
{
	struct net_conf *nc;
	int timeout, good = 0;

	if (!*socket1 || !*socket2)
		return false;

	rcu_read_lock();
	nc = rcu_dereference(transport->net_conf);
	timeout = (nc->sock_check_timeo ?: nc->ping_timeo) * HZ / 10;
	rcu_read_unlock();
	schedule_timeout_interruptible(timeout);

	good += dtt_socket_ok_or_free(socket1);
	good += dtt_socket_ok_or_free(socket2);

	if (good == 0)
		*first_path = NULL;

	return good == 2;
}

static struct dtt_path *dtt_wait_connect_cond(struct drbd_transport *transport)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);
	struct drbd_listener *listener;
	struct drbd_path *drbd_path;
	struct dtt_path *path = NULL;
	bool rv = false;

	spin_lock(&tcp_transport->paths_lock);
	list_for_each_entry(drbd_path, &transport->paths, list) {
		path = container_of(drbd_path, struct dtt_path, path);
		listener = drbd_path->listener;

		spin_lock_bh(&listener->waiters_lock);
		rv = listener->pending_accepts > 0 || !list_empty(&path->sockets);
		spin_unlock_bh(&listener->waiters_lock);

		if (rv)
			break;
	}
	spin_unlock(&tcp_transport->paths_lock);

	return rv ? path : NULL;
}

static void unregister_state_change(struct sock *sock, struct dtt_listener *listener)
{
	write_lock_bh(&sock->sk_callback_lock);
	sock->sk_state_change = listener->original_sk_state_change;
	sock->sk_user_data = NULL;
	write_unlock_bh(&sock->sk_callback_lock);
}

static int dtt_wait_for_connect(struct drbd_transport *transport,
				struct drbd_listener *drbd_listener, struct socket **socket,
				struct dtt_path **ret_path)
{
	struct dtt_socket_container *socket_c;
	struct sockaddr_storage peer_addr;
	int connect_int, err = 0;
	long timeo;
	struct socket *s_estab = NULL;
	struct net_conf *nc;
	struct drbd_path *drbd_path2;
	struct dtt_listener *listener = container_of(drbd_listener, struct dtt_listener, listener);
	struct dtt_path *path = NULL;

	rcu_read_lock();
	nc = rcu_dereference(transport->net_conf);
	if (!nc) {
		rcu_read_unlock();
		return -EINVAL;
	}
	connect_int = nc->connect_int;
	rcu_read_unlock();

	timeo = connect_int * HZ;
	timeo += (prandom_u32() & 1) ? timeo / 7 : -timeo / 7; /* 28.5% random jitter */

retry:
	timeo = wait_event_interruptible_timeout(listener->wait,
			(path = dtt_wait_connect_cond(transport)),
			timeo);
	if (timeo <= 0)
		return -EAGAIN;

	spin_lock_bh(&listener->listener.waiters_lock);
	socket_c = list_first_entry_or_null(&path->sockets, struct dtt_socket_container, list);
	if (socket_c) {
		s_estab = socket_c->socket;
		list_del(&socket_c->list);
		kfree(socket_c);
	} else if (listener->listener.pending_accepts > 0) {
		listener->listener.pending_accepts--;
		spin_unlock_bh(&listener->listener.waiters_lock);

		s_estab = NULL;
		err = kernel_accept(listener->s_listen, &s_estab, O_NONBLOCK);
		if (err < 0)
			return err;

		/* The established socket inherits the sk_state_change callback
		   from the listening socket. */
		unregister_state_change(s_estab->sk, listener);

		s_estab->ops->getname(s_estab, (struct sockaddr *)&peer_addr, 2);

		spin_lock_bh(&listener->listener.waiters_lock);
		drbd_path2 = drbd_find_path_by_addr(&listener->listener, &peer_addr);
		if (!drbd_path2) {
			struct sockaddr_in6 *from_sin6;
			struct sockaddr_in *from_sin;

			switch (peer_addr.ss_family) {
			case AF_INET6:
				from_sin6 = (struct sockaddr_in6 *)&peer_addr;
				tr_notice(transport, "Closing unexpected connection from "
				       "%pI6\n", &from_sin6->sin6_addr);
				break;
			default:
				from_sin = (struct sockaddr_in *)&peer_addr;
				tr_notice(transport, "Closing unexpected connection from "
					 "%pI4\n", &from_sin->sin_addr);
				break;
			}

			goto retry_locked;
		}
		if (drbd_path2 != &path->path) {
			struct dtt_path *path2 =
				container_of(drbd_path2, struct dtt_path, path);

			socket_c = kmalloc(sizeof(*socket_c), GFP_ATOMIC);
			if (!socket_c) {
				tr_info(transport, /* path2->transport, */
					"No mem, dropped an incoming connection\n");
				goto retry_locked;
			}

			socket_c->socket = s_estab;
			s_estab = NULL;
			list_add_tail(&socket_c->list, &path2->sockets);
			wake_up(&listener->wait);
			goto retry_locked;
		}
		if (s_estab->sk->sk_state != TCP_ESTABLISHED)
			goto retry_locked;
	}
	spin_unlock_bh(&listener->listener.waiters_lock);
	*socket = s_estab;
	*ret_path = path;
	return 0;

retry_locked:
	spin_unlock_bh(&listener->listener.waiters_lock);
	if (s_estab) {
		kernel_sock_shutdown(s_estab, SHUT_RDWR);
		sock_release(s_estab);
		s_estab = NULL;
	}
	goto retry;
}

static int dtt_receive_first_packet(struct drbd_tcp_transport *tcp_transport, struct socket *socket)
{
	struct drbd_transport *transport = &tcp_transport->transport;
	struct p_header80 *h = tcp_transport->rbuf[DATA_STREAM].base;
	const unsigned int header_size = sizeof(*h);
	struct net_conf *nc;
	int err;

	rcu_read_lock();
	nc = rcu_dereference(transport->net_conf);
	if (!nc) {
		rcu_read_unlock();
		return -EIO;
	}
	socket->sk->sk_rcvtimeo = nc->ping_timeo * 4 * HZ / 10;
	rcu_read_unlock();

	err = dtt_recv_short(socket, h, header_size, 0);
	if (err != header_size) {
		if (err >= 0)
			err = -EIO;
		return err;
	}
	if (h->magic != cpu_to_be32(DRBD_MAGIC)) {
		tr_err(transport, "Wrong magic value 0x%08x in receive_first_packet\n",
			 be32_to_cpu(h->magic));
		return -EINVAL;
	}
	return be16_to_cpu(h->command);
}

static void dtt_incoming_connection(struct sock *sock)
{
	struct dtt_listener *listener = sock->sk_user_data;
	void (*state_change)(struct sock *sock);

	state_change = listener->original_sk_state_change;
	state_change(sock);

	spin_lock(&listener->listener.waiters_lock);
	listener->listener.pending_accepts++;
	spin_unlock(&listener->listener.waiters_lock);
	wake_up(&listener->wait);
}

static void dtt_destroy_listener(struct drbd_listener *generic_listener)
{
	struct dtt_listener *listener =
		container_of(generic_listener, struct dtt_listener, listener);

	unregister_state_change(listener->s_listen->sk, listener);
	sock_release(listener->s_listen);
	kfree(listener);
}

static int dtt_init_listener(struct drbd_transport *transport,
			     const struct sockaddr *addr,
			     struct drbd_listener *drbd_listener)
{
	int err, sndbuf_size, rcvbuf_size, addr_len;
	struct sockaddr_storage my_addr;
	struct dtt_listener *listener = container_of(drbd_listener, struct dtt_listener, listener);
	struct socket *s_listen;
	struct net_conf *nc;
	const char *what = "";

	rcu_read_lock();
	nc = rcu_dereference(transport->net_conf);
	if (!nc) {
		rcu_read_unlock();
		return -EINVAL;
	}
	sndbuf_size = nc->sndbuf_size;
	rcvbuf_size = nc->rcvbuf_size;
	rcu_read_unlock();

	my_addr = *(struct sockaddr_storage *)addr;

	err = sock_create_kern(&init_net, my_addr.ss_family, SOCK_STREAM, IPPROTO_TCP, &s_listen);
	if (err) {
		s_listen = NULL;
		what = "sock_create_kern";
		goto out;
	}

	s_listen->sk->sk_reuse = SK_CAN_REUSE; /* SO_REUSEADDR */
	dtt_setbufsize(s_listen, sndbuf_size, rcvbuf_size);

	addr_len = addr->sa_family == AF_INET6 ? sizeof(struct sockaddr_in6)
		: sizeof(struct sockaddr_in);

	err = s_listen->ops->bind(s_listen, (struct sockaddr *)&my_addr, addr_len);
	if (err < 0) {
		what = "bind before listen";
		goto out;
	}

	listener->s_listen = s_listen;
	write_lock_bh(&s_listen->sk->sk_callback_lock);
	listener->original_sk_state_change = s_listen->sk->sk_state_change;
	s_listen->sk->sk_state_change = dtt_incoming_connection;
	s_listen->sk->sk_user_data = listener;
	write_unlock_bh(&s_listen->sk->sk_callback_lock);

	err = s_listen->ops->listen(s_listen, DRBD_PEERS_MAX * 2);
	if (err < 0) {
		what = "listen";
		goto out;
	}

	listener->listener.listen_addr = my_addr;
	listener->listener.destroy = dtt_destroy_listener;
	init_waitqueue_head(&listener->wait);

	return 0;
out:
	if (s_listen)
		sock_release(s_listen);

	if (err < 0 &&
	    err != -EAGAIN && err != -EINTR && err != -ERESTARTSYS && err != -EADDRINUSE &&
	    err != -EADDRNOTAVAIL)
		tr_err(transport, "%s failed, err = %d\n", what, err);

	return err;
}

static void dtt_cleanup_accepted_sockets(struct dtt_path *path)
{
	while (!list_empty(&path->sockets)) {
		struct dtt_socket_container *socket_c =
			list_first_entry(&path->sockets, struct dtt_socket_container, list);

		list_del(&socket_c->list);
		kernel_sock_shutdown(socket_c->socket, SHUT_RDWR);
		sock_release(socket_c->socket);
		kfree(socket_c);
	}
}

static void dtt_put_listeners(struct drbd_transport *transport)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);
	struct drbd_path *drbd_path;

	spin_lock(&tcp_transport->paths_lock);
	clear_bit(DTT_CONNECTING, &tcp_transport->flags);
	spin_unlock(&tcp_transport->paths_lock);

	for_each_path_ref(drbd_path, transport) {
		struct dtt_path *path = container_of(drbd_path, struct dtt_path, path);

		drbd_put_listener(drbd_path);
		dtt_cleanup_accepted_sockets(path);
	}
}

static struct dtt_path *dtt_next_path(struct drbd_tcp_transport *tcp_transport, struct dtt_path *path)
{
	struct drbd_transport *transport = &tcp_transport->transport;
	struct drbd_path *drbd_path;

	spin_lock(&tcp_transport->paths_lock);
	if (list_is_last(&path->path.list, &transport->paths))
		drbd_path = list_first_entry(&transport->paths, struct drbd_path, list);
	else
		drbd_path = list_next_entry(&path->path, list);
	spin_unlock(&tcp_transport->paths_lock);

	return container_of(drbd_path, struct dtt_path, path);
}

static int dtt_connect(struct drbd_transport *transport)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);
	struct drbd_path *drbd_path;
	struct dtt_path *connect_to_path, *first_path = NULL;
	struct socket *dsocket, *csocket;
	struct net_conf *nc;
	int timeout, err;
	bool ok;

	dsocket = NULL;
	csocket = NULL;


	for_each_path_ref(drbd_path, transport) {
		struct dtt_path *path = container_of(drbd_path, struct dtt_path, path);

		dtt_cleanup_accepted_sockets(path);
	}

	spin_lock(&tcp_transport->paths_lock);
	set_bit(DTT_CONNECTING, &tcp_transport->flags);

	err = -EDESTADDRREQ;
	if (list_empty(&transport->paths)) {
		spin_unlock(&tcp_transport->paths_lock);
		goto out;
	}

	list_for_each_entry(drbd_path, &transport->paths, list) {
		if (!drbd_path->listener) {
			kref_get(&drbd_path->kref);
			spin_unlock(&tcp_transport->paths_lock);
			err = drbd_get_listener(transport, drbd_path, dtt_init_listener);
			kref_put(&drbd_path->kref, drbd_destroy_path);
			if (err)
				goto out;
			spin_lock(&tcp_transport->paths_lock);
			drbd_path = list_first_entry_or_null(&transport->paths, struct drbd_path, list);
			if (drbd_path)
				continue;
			else
				break;
		}
	}

	drbd_path = list_first_entry(&transport->paths, struct drbd_path, list);
	connect_to_path = container_of(drbd_path, struct dtt_path, path);
	spin_unlock(&tcp_transport->paths_lock);

	ok = false;
	do {
		struct socket *s = NULL;

		err = dtt_try_connect(transport, connect_to_path, &s);
		if (err < 0 && err != -EAGAIN)
			goto out;

		if (s) {
			bool use_for_data;

			if (first_path && first_path != connect_to_path) {
				tr_info(transport, "initial paths crossed A - fail over\n");
				dtt_socket_free(&dsocket);
				dtt_socket_free(&csocket);
			}

			first_path = connect_to_path;

			if (!dsocket && !csocket) {
				use_for_data = dtt_path_cmp_addr(first_path);
			} else if (!dsocket) {
				use_for_data = true;
			} else {
				if (csocket) {
					tr_err(transport, "Logic error in conn_connect()\n");
					goto out_eagain;
				}
				use_for_data = false;
			}

			if (use_for_data) {
				dsocket = s;
				dtt_send_first_packet(tcp_transport, dsocket, P_INITIAL_DATA, DATA_STREAM);
			} else {
				clear_bit(RESOLVE_CONFLICTS, &transport->flags);
				csocket = s;
				dtt_send_first_packet(tcp_transport, csocket, P_INITIAL_META, CONTROL_STREAM);
			}
		} else if (!first_path)
			connect_to_path = dtt_next_path(tcp_transport, connect_to_path);

		if (dtt_connection_established(transport, &dsocket, &csocket, &first_path))
			break;

retry:
		s = NULL;
		err = dtt_wait_for_connect(transport, connect_to_path->path.listener, &s, &connect_to_path);
		if (err < 0 && err != -EAGAIN)
			goto out;

		if (s) {
			int fp = dtt_receive_first_packet(tcp_transport, s);

			if (first_path && first_path != connect_to_path) {
				tr_info(transport, "initial paths crossed P - fail over\n");
				dtt_socket_free(&dsocket);
				dtt_socket_free(&csocket);
			}

			first_path = connect_to_path;

			dtt_socket_ok_or_free(&dsocket);
			dtt_socket_ok_or_free(&csocket);
			switch (fp) {
			case P_INITIAL_DATA:
				if (dsocket) {
					tr_warn(transport, "initial packet S crossed\n");
					kernel_sock_shutdown(dsocket, SHUT_RDWR);
					sock_release(dsocket);
					dsocket = s;
					goto randomize;
				}
				dsocket = s;
				break;
			case P_INITIAL_META:
				set_bit(RESOLVE_CONFLICTS, &transport->flags);
				if (csocket) {
					tr_warn(transport, "initial packet M crossed\n");
					kernel_sock_shutdown(csocket, SHUT_RDWR);
					sock_release(csocket);
					csocket = s;
					goto randomize;
				}
				csocket = s;
				break;
			default:
				tr_warn(transport, "Error receiving initial packet\n");
				kernel_sock_shutdown(s, SHUT_RDWR);
				sock_release(s);
randomize:
				if (prandom_u32() & 1)
					goto retry;
			}
		}

		if (drbd_should_abort_listening(transport))
			goto out_eagain;

		ok = dtt_connection_established(transport, &dsocket, &csocket, &first_path);
	} while (!ok);

	TR_ASSERT(transport, first_path == connect_to_path);
	connect_to_path->path.established = true;
	drbd_path_event(transport, &connect_to_path->path);
	dtt_put_listeners(transport);

	dsocket->sk->sk_reuse = SK_CAN_REUSE; /* SO_REUSEADDR */
	csocket->sk->sk_reuse = SK_CAN_REUSE; /* SO_REUSEADDR */

	dsocket->sk->sk_allocation = GFP_NOIO;
	csocket->sk->sk_allocation = GFP_NOIO;

	dsocket->sk->sk_priority = TC_PRIO_INTERACTIVE_BULK;
	csocket->sk->sk_priority = TC_PRIO_INTERACTIVE;

	/* NOT YET ...
	 * sock.socket->sk->sk_sndtimeo = transport->net_conf->timeout*HZ/10;
	 * sock.socket->sk->sk_rcvtimeo = MAX_SCHEDULE_TIMEOUT;
	 * first set it to the P_CONNECTION_FEATURES timeout,
	 * which we set to 4x the configured ping_timeout. */

	/* we don't want delays.
	 * we use tcp_sock_set_cork where appropriate, though */
	tcp_sock_set_nodelay(dsocket->sk);
	tcp_sock_set_nodelay(csocket->sk);

	tcp_transport->stream[DATA_STREAM] = dsocket;
	tcp_transport->stream[CONTROL_STREAM] = csocket;

	rcu_read_lock();
	nc = rcu_dereference(transport->net_conf);

	timeout = nc->timeout * HZ / 10;
	rcu_read_unlock();

	dsocket->sk->sk_sndtimeo = timeout;
	csocket->sk->sk_sndtimeo = timeout;

	sock_set_keepalive(dsocket->sk);

	return 0;

out_eagain:
	err = -EAGAIN;

out:
	dtt_put_listeners(transport);

	if (dsocket) {
		kernel_sock_shutdown(dsocket, SHUT_RDWR);
		sock_release(dsocket);
	}
	if (csocket) {
		kernel_sock_shutdown(csocket, SHUT_RDWR);
		sock_release(csocket);
	}

	return err;
}

static void dtt_set_rcvtimeo(struct drbd_transport *transport, enum drbd_stream stream, long timeout)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);
	struct socket *socket = tcp_transport->stream[stream];

	if (!socket)
		return;

	socket->sk->sk_rcvtimeo = timeout;
}

static long dtt_get_rcvtimeo(struct drbd_transport *transport, enum drbd_stream stream)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);
	struct socket *socket = tcp_transport->stream[stream];

	if (!socket)
		return -ENOTCONN;

	return socket->sk->sk_rcvtimeo;
}

static bool dtt_stream_ok(struct drbd_transport *transport, enum drbd_stream stream)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);
	struct socket *socket = tcp_transport->stream[stream];

	return socket && socket->sk;
}

static void dtt_update_congested(struct drbd_tcp_transport *tcp_transport)
{
	struct socket *socket = tcp_transport->stream[DATA_STREAM];
	struct sock *sock;

	if (!socket)
		return;

	sock = socket->sk;
	if (sock->sk_wmem_queued > sock->sk_sndbuf * 4 / 5)
		set_bit(NET_CONGESTED, &tcp_transport->transport.flags);
}

static int dtt_send_page(struct drbd_transport *transport, enum drbd_stream stream,
			 struct page *page, int offset, size_t size, unsigned msg_flags)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);
	struct socket *socket = tcp_transport->stream[stream];
	int len = size;
	int err = -EIO;

	if (!socket)
		return -ENOTCONN;

	msg_flags |= MSG_NOSIGNAL;
	dtt_update_congested(tcp_transport);
	do {
		int sent;

		sent = socket->ops->sendpage(socket, page, offset, len, msg_flags);
		if (sent <= 0) {
			if (sent == -EAGAIN) {
				if (drbd_stream_send_timed_out(transport, stream))
					break;
				continue;
			}
			tr_warn(transport, "%s: size=%d len=%d sent=%d\n",
			     __func__, (int)size, len, sent);
			if (sent < 0)
				err = sent;
			break;
		}
		len    -= sent;
		offset += sent;
		/* NOTE: it may take up to twice the socket timeout to have it
		 * return -EAGAIN, the first timeout will likely happen with a
		 * partial send, masking the timeout.  Maybe we want to export
		 * drbd_stream_should_continue_after_partial_send(transport, stream)
		 * and add that to the while() condition below.
		 */
	} while (len > 0 /* THINK && peer_device->repl_state[NOW] >= L_ESTABLISHED */);
	clear_bit(NET_CONGESTED, &tcp_transport->transport.flags);

	if (len == 0)
		err = 0;

	return err;
}

static int dtt_send_zc_bio(struct drbd_transport *transport, struct bio *bio)
{
	struct bio_vec bvec;
	struct bvec_iter iter;

	bio_for_each_segment(bvec, bio, iter) {
		int err;

		err = dtt_send_page(transport, DATA_STREAM, bvec.bv_page,
				      bvec.bv_offset, bvec.bv_len,
				      bio_iter_last(bvec, iter) ? 0 : MSG_MORE);
		if (err)
			return err;

		if (bio_op(bio) == REQ_OP_WRITE_SAME)
			break;
	}
	return 0;
}

static bool dtt_hint(struct drbd_transport *transport, enum drbd_stream stream,
		enum drbd_tr_hints hint)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);
	bool rv = true;
	struct socket *socket = tcp_transport->stream[stream];

	if (!socket)
		return false;

	switch (hint) {
	case CORK:
		tcp_sock_set_cork(socket->sk, true);
		break;
	case UNCORK:
		tcp_sock_set_cork(socket->sk, false);
		break;
	case NODELAY:
		tcp_sock_set_nodelay(socket->sk);
		break;
	case NOSPACE:
		if (socket->sk->sk_socket)
			set_bit(SOCK_NOSPACE, &socket->sk->sk_socket->flags);
		break;
	case QUICKACK:
		tcp_sock_set_quickack(socket->sk, 2);
		break;
	default: /* not implemented, but should not trigger error handling */
		return true;
	}

	return rv;
}

static void dtt_debugfs_show_stream(struct seq_file *m, struct socket *socket)
{
	struct sock *sk = socket->sk;
	struct tcp_sock *tp = tcp_sk(sk);

	seq_printf(m, "unread receive buffer: %u Byte\n",
		   tp->rcv_nxt - tp->copied_seq);
	seq_printf(m, "unacked send buffer: %u Byte\n",
		   tp->write_seq - tp->snd_una);
	seq_printf(m, "send buffer size: %u Byte\n", sk->sk_sndbuf);
	seq_printf(m, "send buffer used: %u Byte\n", sk->sk_wmem_queued);
}

static void dtt_debugfs_show(struct drbd_transport *transport, struct seq_file *m)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);
	enum drbd_stream i;

	/* BUMP me if you change the file format/content/presentation */
	seq_printf(m, "v: %u\n\n", 0);

	for (i = DATA_STREAM; i <= CONTROL_STREAM ; i++) {
		struct socket *socket = tcp_transport->stream[i];

		if (socket) {
			seq_printf(m, "%s stream\n", i == DATA_STREAM ? "data" : "control");
			dtt_debugfs_show_stream(m, socket);
		}
	}

}

static int dtt_add_path(struct drbd_transport *transport, struct drbd_path *drbd_path)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);
	struct dtt_path *path = container_of(drbd_path, struct dtt_path, path);
	bool active;

	drbd_path->established = false;
	INIT_LIST_HEAD(&path->sockets);
retry:
	active = test_bit(DTT_CONNECTING, &tcp_transport->flags);
	if (!active && drbd_path->listener)
		drbd_put_listener(drbd_path);

	if (active && !drbd_path->listener) {
		int err = drbd_get_listener(transport, drbd_path, dtt_init_listener);
		if (err)
			return err;
	}

	spin_lock(&tcp_transport->paths_lock);
	if (active != test_bit(DTT_CONNECTING, &tcp_transport->flags)) {
		spin_unlock(&tcp_transport->paths_lock);
		goto retry;
	}
	list_add_tail(&drbd_path->list, &transport->paths);
	spin_unlock(&tcp_transport->paths_lock);

	return 0;
}

static int dtt_remove_path(struct drbd_transport *transport, struct drbd_path *drbd_path)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);
	struct dtt_path *path = container_of(drbd_path, struct dtt_path, path);

	if (drbd_path->established)
		return -EBUSY;

	spin_lock(&tcp_transport->paths_lock);
	list_del_init(&drbd_path->list);
	spin_unlock(&tcp_transport->paths_lock);
	drbd_put_listener(&path->path);

	return 0;
}

static int __init dtt_initialize(void)
{
	return drbd_register_transport_class(&tcp_transport_class,
					     DRBD_TRANSPORT_API_VERSION,
					     sizeof(struct drbd_transport));
}

static void __exit dtt_cleanup(void)
{
	drbd_unregister_transport_class(&tcp_transport_class);
}

module_init(dtt_initialize)
module_exit(dtt_cleanup)
