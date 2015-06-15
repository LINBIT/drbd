/*
   drbd_transport_tcp.c

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
#include <linux/errno.h>
#include <linux/socket.h>
#include <linux/pkt_sched.h>
#include <linux/net.h>
#include <linux/tcp.h>
#include <linux/highmem.h>
#include <linux/drbd_genl_api.h>
#include <drbd_protocol.h>
#include <drbd_transport.h>
#include "drbd_wrappers.h"


MODULE_AUTHOR("Roland Kammerer <roland.kammerer@linbit.com>");
MODULE_DESCRIPTION("TCP (SDP, SSOCKS) transport layer for DRBD");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0.0");

struct buffer {
	void *base;
	void *pos;
};

struct drbd_tcp_transport {
	struct drbd_transport transport; /* Must be first! */
	struct socket *stream[2];
	struct buffer rbuf[2];
	bool in_use;
};

struct dtt_listener {
	struct drbd_listener listener;
	void (*original_sk_state_change)(struct sock *sk);
	struct socket *s_listen;
};

struct dtt_waiter {
	struct drbd_waiter waiter;
	struct socket *socket;
};

static int dtt_init(struct drbd_transport *transport);
static void dtt_free(struct drbd_transport *transport, enum drbd_tr_free_op free_op);
static int dtt_connect(struct drbd_transport *transport);
static int dtt_recv(struct drbd_transport *transport, enum drbd_stream stream, void **buf, size_t size, int flags);
static int dtt_recv_pages(struct drbd_transport *transport, struct page **page, size_t size);
static void dtt_stats(struct drbd_transport *transport, struct drbd_transport_stats *stats);
static void dtt_set_rcvtimeo(struct drbd_transport *transport, enum drbd_stream stream, long timeout);
static long dtt_get_rcvtimeo(struct drbd_transport *transport, enum drbd_stream stream);
static int dtt_send_page(struct drbd_transport *transport, enum drbd_stream, struct page *page,
		int offset, size_t size, unsigned msg_flags);
static bool dtt_stream_ok(struct drbd_transport *transport, enum drbd_stream stream);
static bool dtt_hint(struct drbd_transport *transport, enum drbd_stream stream, enum drbd_tr_hints hint);
static void dtt_debugfs_show(struct drbd_transport *transport, struct seq_file *m);
static void dtt_update_congested(struct drbd_tcp_transport *tcp_transport);
static int dtt_add_path(struct drbd_transport *, struct drbd_path *path);
static int dtt_remove_path(struct drbd_transport *, struct drbd_path *);

static struct drbd_transport_class tcp_transport_class = {
	.name = "tcp",
	.instance_size = sizeof(struct drbd_tcp_transport),
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
	.stream_ok = dtt_stream_ok,
	.hint = dtt_hint,
	.debugfs_show = dtt_debugfs_show,
	.add_path = dtt_add_path,
	.remove_path = dtt_remove_path,
};


static void dtt_nodelay(struct socket *socket)
{
	int val = 1;
	(void) kernel_setsockopt(socket, SOL_TCP, TCP_NODELAY, (char *)&val, sizeof(val));
}

int dtt_init(struct drbd_transport *transport)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);
	enum drbd_stream i;

	tcp_transport->transport.ops = &dtt_ops;
	tcp_transport->transport.class = &tcp_transport_class;
	for (i = DATA_STREAM; i <= CONTROL_STREAM ; i++) {
		void *buffer = (void *)__get_free_page(GFP_KERNEL);
		if (!buffer)
			goto fail;
		tcp_transport->rbuf[i].base = buffer;
		tcp_transport->rbuf[i].pos = buffer;
	}
	tcp_transport->in_use = false;

	return 0;
fail:
	free_page((unsigned long)tcp_transport->rbuf[0].base);
	return -ENOMEM;
}

static struct drbd_path* dtt_path(struct drbd_transport *transport)
{
	return list_first_entry_or_null(&transport->paths, struct drbd_path, list);
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
	struct drbd_path *path;

	/* free the socket specific stuff,
	 * mutexes are handled by caller */

	for (i = DATA_STREAM; i <= CONTROL_STREAM; i++) {
		if (tcp_transport->stream[i]) {
			dtt_free_one_sock(tcp_transport->stream[i]);
			tcp_transport->stream[i] = NULL;
		}
	}
	tcp_transport->in_use = false;

	if (free_op == DESTROY_TRANSPORT) {
		for (i = DATA_STREAM; i <= CONTROL_STREAM; i++) {
			free_page((unsigned long)tcp_transport->rbuf[i].base);
			tcp_transport->rbuf[i].base = NULL;
		}
		path = dtt_path(transport);
		if (path) {
			list_del(&path->list);
			kfree(path);
		}
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
		/* STRANGE
		 * tcp_sendmsg does _not_ use its size parameter at all ?
		 *
		 * -EAGAIN on timeout, -EINTR on signal.
		 */
/* THINK
 * do we need to block DRBD_SIG if sock == &meta.socket ??
 * otherwise wake_asender() might interrupt some send_*Ack !
 */
		rv = kernel_sendmsg(socket, &msg, &iov, 1, size);
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

static int dtt_recv_pages(struct drbd_transport *transport, struct page **pages, size_t size)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);
	struct socket *socket = tcp_transport->stream[DATA_STREAM];
	struct page *all_pages, *page;
	int err;

	all_pages = drbd_alloc_pages(transport, DIV_ROUND_UP(size, PAGE_SIZE), GFP_TRY);
	if (!all_pages)
		return -ENOMEM;

	page = all_pages;
	page_chain_for_each(page) {
		size_t len = min_t(int, size, PAGE_SIZE);
		void *data = kmap(page);
		err = dtt_recv_short(socket, data, len, 0);
		kunmap(page);
		if (err < 0)
			goto fail;
		size -= len;
	}

	*pages = all_pages;
	return 0;
fail:
	drbd_free_pages(transport, all_pages, 0);
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

static int dtt_try_connect(struct drbd_transport *transport, struct socket **ret_socket)
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

	my_addr = dtt_path(transport)->my_addr;
	if (my_addr.ss_family == AF_INET6)
		((struct sockaddr_in6 *)&my_addr)->sin6_port = 0;
	else
		((struct sockaddr_in *)&my_addr)->sin_port = 0; /* AF_INET & AF_SCI */

	/* In some cases, the network stack can end up overwriting
	   peer_addr.ss_family, so use a copy here. */
	peer_addr = dtt_path(transport)->peer_addr;

	what = "sock_create_kern";
	err = sock_create_kern(my_addr.ss_family, SOCK_STREAM, IPPROTO_TCP, &socket);
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
	err = socket->ops->bind(socket, (struct sockaddr *) &my_addr, dtt_path(transport)->my_addr_len);
	if (err < 0)
		goto out;

	/* connect may fail, peer not yet available.
	 * stay C_CONNECTING, don't go Disconnecting! */
	what = "connect";
	err = socket->ops->connect(socket, (struct sockaddr *) &peer_addr,
				   dtt_path(transport)->peer_addr_len, 0);
	if (err < 0) {
		switch (err) {
		case -ETIMEDOUT:
		case -EINPROGRESS:
		case -EINTR:
		case -ERESTARTSYS:
		case -ECONNREFUSED:
		case -ENETUNREACH:
		case -EHOSTDOWN:
		case -EHOSTUNREACH:
			err = -EAGAIN;
		}
	}

out:
	if (err < 0) {
		if (socket)
			sock_release(socket);
		if (err != -EAGAIN)
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
 * dtt_socket_ok_or_free() - Free the socket if its connection is not okay
 * @sock:	pointer to the pointer to the socket.
 */
static bool dtt_socket_ok_or_free(struct socket **socket)
{
	int rr;
	char tb[4];

	if (!*socket)
		return false;

	rr = dtt_recv_short(*socket, tb, 4, MSG_DONTWAIT | MSG_PEEK);

	if (rr > 0 || rr == -EAGAIN) {
		return true;
	} else {
		sock_release(*socket);
		*socket = NULL;
		return false;
	}
}

static bool dtt_connection_established(struct drbd_transport *transport,
				   struct socket **socket1,
				   struct socket **socket2)
{
	struct net_conf *nc;
	int timeout;

	if (!*socket1 || !*socket2)
		return false;

	rcu_read_lock();
	nc = rcu_dereference(transport->net_conf);
	timeout = (nc->sock_check_timeo ?: nc->ping_timeo) * HZ / 10;
	rcu_read_unlock();
	schedule_timeout_interruptible(timeout);

	dtt_socket_ok_or_free(socket1);
	dtt_socket_ok_or_free(socket2);

	return *socket1 && *socket2;
}

static bool dtt_wait_connect_cond(struct dtt_waiter *waiter)
{
	struct drbd_listener *listener = waiter->waiter.listener;
	bool rv;

	spin_lock_bh(&listener->waiters_lock);
	rv = waiter->waiter.listener->pending_accepts > 0 || waiter->socket != NULL;
	spin_unlock_bh(&listener->waiters_lock);

	return rv;
}

static void unregister_state_change(struct sock *sock, struct dtt_listener *listener)
{
	write_lock_bh(&sock->sk_callback_lock);
	sock->sk_state_change = listener->original_sk_state_change;
	sock->sk_user_data = NULL;
	write_unlock_bh(&sock->sk_callback_lock);
}

static int dtt_wait_for_connect(struct dtt_waiter *waiter, struct socket **socket)
{
	struct sockaddr_storage peer_addr;
	int connect_int, peer_addr_len, err = 0;
	long timeo;
	struct socket *s_estab;
	struct net_conf *nc;
	struct drbd_waiter *waiter2_gen;
	struct dtt_listener *listener =
		container_of(waiter->waiter.listener, struct dtt_listener, listener);

	rcu_read_lock();
	nc = rcu_dereference(waiter->waiter.transport->net_conf);
	if (!nc) {
		rcu_read_unlock();
		return -EINVAL;
	}
	connect_int = nc->connect_int;
	rcu_read_unlock();

	timeo = connect_int * HZ;
	timeo += (prandom_u32() & 1) ? timeo / 7 : -timeo / 7; /* 28.5% random jitter */

retry:
	timeo = wait_event_interruptible_timeout(waiter->waiter.wait, dtt_wait_connect_cond(waiter), timeo);
	if (timeo <= 0)
		return -EAGAIN;

	spin_lock_bh(&listener->listener.waiters_lock);
	if (waiter->socket) {
		s_estab = waiter->socket;
		waiter->socket = NULL;
	} else if (listener->listener.pending_accepts > 0) {
		listener->listener.pending_accepts--;
		spin_unlock_bh(&listener->listener.waiters_lock);

		s_estab = NULL;
		err = kernel_accept(listener->s_listen, &s_estab, 0);
		if (err < 0)
			return err;

		/* The established socket inherits the sk_state_change callback
		   from the listening socket. */
		unregister_state_change(s_estab->sk, listener);

		s_estab->ops->getname(s_estab, (struct sockaddr *)&peer_addr, &peer_addr_len, 2);

		spin_lock_bh(&listener->listener.waiters_lock);
		waiter2_gen = drbd_find_waiter_by_addr(waiter->waiter.listener, &peer_addr);
		if (!waiter2_gen) {
			struct sockaddr_in6 *from_sin6, *to_sin6;
			struct sockaddr_in *from_sin, *to_sin;
			struct drbd_transport *transport = waiter->waiter.transport;

			switch (peer_addr.ss_family) {
			case AF_INET6:
				from_sin6 = (struct sockaddr_in6 *)&peer_addr;
				to_sin6 = (struct sockaddr_in6 *)&dtt_path(transport)->my_addr;
				tr_err(transport, "Closing unexpected connection from "
					 "%pI6 to port %u\n",
					 &from_sin6->sin6_addr,
					 be16_to_cpu(to_sin6->sin6_port));
				break;
			default:
				from_sin = (struct sockaddr_in *)&peer_addr;
				to_sin = (struct sockaddr_in *)&dtt_path(transport)->my_addr;
				tr_err(transport, "Closing unexpected connection from "
					 "%pI4 to port %u\n",
					 &from_sin->sin_addr,
					 be16_to_cpu(to_sin->sin_port));
				break;
			}

			goto retry_locked;
		}
		if (waiter2_gen != &waiter->waiter) {
			struct dtt_waiter *waiter2 =
				container_of(waiter2_gen, struct dtt_waiter, waiter);

			if (waiter2->socket) {
				tr_err(waiter2->waiter.transport,
					 "Receiver busy; rejecting incoming connection\n");
				goto retry_locked;
			}
			waiter2->socket = s_estab;
			s_estab = NULL;
			wake_up(&waiter2->waiter.wait);
			goto retry_locked;
		}
	}
	spin_unlock_bh(&listener->listener.waiters_lock);
	*socket = s_estab;
	return 0;

retry_locked:
	spin_unlock_bh(&listener->listener.waiters_lock);
	if (s_estab) {
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
	if (sock->sk_state == TCP_ESTABLISHED) {
		struct drbd_waiter *waiter;

		spin_lock(&listener->listener.waiters_lock);
		listener->listener.pending_accepts++;
		waiter = list_entry(listener->listener.waiters.next, struct drbd_waiter, list);
		wake_up(&waiter->wait);
		spin_unlock(&listener->listener.waiters_lock);
	}
	state_change(sock);
}

static void dtt_destroy_listener(struct drbd_listener *generic_listener)
{
	struct dtt_listener *listener =
		container_of(generic_listener, struct dtt_listener, listener);

	unregister_state_change(listener->s_listen->sk, listener);
	sock_release(listener->s_listen);
	kfree(listener);
}

static int dtt_create_listener(struct drbd_transport *transport, struct drbd_listener **ret_listener)
{
	int err, sndbuf_size, rcvbuf_size;
	struct sockaddr_storage my_addr;
	struct dtt_listener *listener = NULL;
	struct socket *s_listen;
	struct net_conf *nc;
	const char *what;

	rcu_read_lock();
	nc = rcu_dereference(transport->net_conf);
	if (!nc) {
		rcu_read_unlock();
		return -EINVAL;
	}
	sndbuf_size = nc->sndbuf_size;
	rcvbuf_size = nc->rcvbuf_size;
	rcu_read_unlock();

	my_addr = dtt_path(transport)->my_addr;

	what = "sock_create_kern";
	err = sock_create_kern(my_addr.ss_family, SOCK_STREAM, IPPROTO_TCP, &s_listen);
	if (err) {
		s_listen = NULL;
		goto out;
	}

	s_listen->sk->sk_reuse = SK_CAN_REUSE; /* SO_REUSEADDR */
	dtt_setbufsize(s_listen, sndbuf_size, rcvbuf_size);

	what = "bind before listen";
	err = s_listen->ops->bind(s_listen, (struct sockaddr *)&my_addr, dtt_path(transport)->my_addr_len);
	if (err < 0)
		goto out;

	what = "kmalloc";
	listener = kmalloc(sizeof(*listener), GFP_KERNEL);
	if (!listener) {
		err = -ENOMEM;
		goto out;
	}

	listener->s_listen = s_listen;
	write_lock_bh(&s_listen->sk->sk_callback_lock);
	listener->original_sk_state_change = s_listen->sk->sk_state_change;
	s_listen->sk->sk_state_change = dtt_incoming_connection;
	s_listen->sk->sk_user_data = listener;
	write_unlock_bh(&s_listen->sk->sk_callback_lock);

	what = "listen";
	err = s_listen->ops->listen(s_listen, 5);
	if (err < 0)
		goto out;

	listener->listener.listen_addr = my_addr;
	listener->listener.destroy = dtt_destroy_listener;

	*ret_listener = &listener->listener;
	return 0;
out:
	if (s_listen)
		sock_release(s_listen);

	if (err < 0 &&
	    err != -EAGAIN && err != -EINTR && err != -ERESTARTSYS && err != -EADDRINUSE)
		tr_err(transport, "%s failed, err = %d\n", what, err);

	kfree(listener);

	return err;
}

static void dtt_put_listener(struct dtt_waiter *waiter)
{
	drbd_put_listener(&waiter->waiter);
	if (waiter->socket) {
		sock_release(waiter->socket);
		waiter->socket = NULL;
	}
}

static int dtt_connect(struct drbd_transport *transport)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);

	struct socket *dsocket, *csocket;
	struct net_conf *nc;
	struct dtt_waiter waiter;
	int timeout, err;
	bool ok;

	dsocket = NULL;
	csocket = NULL;

	if (!dtt_path(transport))
		return -EDESTADDRREQ;
	tcp_transport->in_use = true;

	waiter.waiter.transport = transport;
	waiter.socket = NULL;
	err = drbd_get_listener(&waiter.waiter, dtt_create_listener);
	if (err)
		return err;

	do {
		struct socket *s = NULL;

		err = dtt_try_connect(transport, &s);
		if (err < 0 && err != -EAGAIN)
			goto out;

		if (s) {
			if (!dsocket) {
				dsocket = s;
				dtt_send_first_packet(tcp_transport, dsocket, P_INITIAL_DATA, DATA_STREAM);
			} else if (!csocket) {
				clear_bit(RESOLVE_CONFLICTS, &transport->flags);
				csocket = s;
				dtt_send_first_packet(tcp_transport, csocket, P_INITIAL_META, CONTROL_STREAM);
			} else {
				tr_err(transport, "Logic error in conn_connect()\n");
				goto out_eagain;
			}
		}

		if (dtt_connection_established(transport, &dsocket, &csocket))
			break;

retry:
		s = NULL;
		err = dtt_wait_for_connect(&waiter, &s);
		if (err < 0 && err != -EAGAIN)
			goto out;

		if (s) {
			int fp = dtt_receive_first_packet(tcp_transport, s);

			dtt_socket_ok_or_free(&dsocket);
			dtt_socket_ok_or_free(&csocket);
			switch (fp) {
			case P_INITIAL_DATA:
				if (dsocket) {
					tr_warn(transport, "initial packet S crossed\n");
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
					sock_release(csocket);
					csocket = s;
					goto randomize;
				}
				csocket = s;
				break;
			default:
				tr_warn(transport, "Error receiving initial packet\n");
				sock_release(s);
randomize:
				if (prandom_u32() & 1)
					goto retry;
			}
		}

		if (drbd_should_abort_listening(transport))
			goto out_eagain;

		ok = dtt_connection_established(transport, &dsocket, &csocket);
	} while (!ok);

	dtt_put_listener(&waiter);

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
	 * we use TCP_CORK where appropriate, though */
	dtt_nodelay(dsocket);
	dtt_nodelay(csocket);

	tcp_transport->stream[DATA_STREAM] = dsocket;
	tcp_transport->stream[CONTROL_STREAM] = csocket;

	rcu_read_lock();
	nc = rcu_dereference(transport->net_conf);

	timeout = nc->timeout * HZ / 10;
	rcu_read_unlock();

	dsocket->sk->sk_sndtimeo = timeout;
	csocket->sk->sk_sndtimeo = timeout;

	return 0;

out_eagain:
	err = -EAGAIN;
out:
	dtt_put_listener(&waiter);
	if (dsocket)
		sock_release(dsocket);
	if (csocket)
		sock_release(csocket);

	return err;
}

static void dtt_set_rcvtimeo(struct drbd_transport *transport, enum drbd_stream stream, long timeout)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);

	struct socket *socket = tcp_transport->stream[stream];

	socket->sk->sk_rcvtimeo = timeout;
}

static long dtt_get_rcvtimeo(struct drbd_transport *transport, enum drbd_stream stream)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);

	struct socket *socket = tcp_transport->stream[stream];

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
	struct sock *sock = tcp_transport->stream[DATA_STREAM]->sk;

	if (sock->sk_wmem_queued > sock->sk_sndbuf * 4 / 5)
		set_bit(NET_CONGESTED, &tcp_transport->transport.flags);
}

static int dtt_send_page(struct drbd_transport *transport, enum drbd_stream stream,
			 struct page *page, int offset, size_t size, unsigned msg_flags)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);
	struct socket *socket = tcp_transport->stream[stream];

	mm_segment_t oldfs = get_fs();
	int len = size;
	int err = -EIO;

	msg_flags |= MSG_NOSIGNAL;
	dtt_update_congested(tcp_transport);
	set_fs(KERNEL_DS);
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
	} while (len > 0 /* THINK && peer_device->repl_state[NOW] >= L_ESTABLISHED */);
	set_fs(oldfs);
	clear_bit(NET_CONGESTED, &tcp_transport->transport.flags);

	if (len == 0)
		err = 0;

	return err;
}

static void dtt_cork(struct socket *socket)
{
	int val = 1;
	(void) kernel_setsockopt(socket, SOL_TCP, TCP_CORK, (char *)&val, sizeof(val));
}

static void dtt_uncork(struct socket *socket)
{
	int val = 0;
	(void) kernel_setsockopt(socket, SOL_TCP, TCP_CORK, (char *)&val, sizeof(val));
}

static void dtt_quickack(struct socket *socket)
{
	int val = 2;
	(void) kernel_setsockopt(socket, SOL_TCP, TCP_QUICKACK, (char *)&val, sizeof(val));
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
		dtt_cork(socket);
		break;
	case UNCORK:
		dtt_uncork(socket);
		break;
	case NODELAY:
		dtt_nodelay(socket);
		break;
	case NOSPACE:
		if (socket->sk->sk_socket)
			set_bit(SOCK_NOSPACE, &socket->sk->sk_socket->flags);
		break;
	case QUICKACK:
		dtt_quickack(socket);
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

static int dtt_add_path(struct drbd_transport *transport, struct drbd_path *path)
{
	if (!list_empty(&transport->paths))
		return -EEXIST;

	list_add(&path->list, &transport->paths);

	return 0;
}

static int dtt_remove_path(struct drbd_transport *transport, struct drbd_path *path)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);
	struct drbd_path *existing = dtt_path(transport);

	if (tcp_transport->in_use)
		return -EBUSY;

	if (path && path == existing) {
		list_del_init(&existing->list);
		return 0;
	}

	return -ENOENT;
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
