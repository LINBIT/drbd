// SPDX-License-Identifier: GPL-2.0-only
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
#include <linux/file.h>
#include <linux/tcp.h>
#include <linux/highmem.h>
#include <linux/bio.h>
#include <linux/drbd_genl_api.h>
#include <linux/drbd_config.h>
#include <linux/tls.h>
#include <net/tcp.h>
#include <net/handshake.h>
#include <net/tls.h>
#include <net/tls_prot.h>
#include "drbd_protocol.h"
#include "drbd_transport.h"


MODULE_AUTHOR("Philipp Reisner <philipp.reisner@linbit.com>");
MODULE_AUTHOR("Lars Ellenberg <lars.ellenberg@linbit.com>");
MODULE_AUTHOR("Roland Kammerer <roland.kammerer@linbit.com>");
MODULE_DESCRIPTION("TCP (SDP, SSOCKS) transport layer for DRBD");
MODULE_LICENSE("GPL");
MODULE_VERSION(REL_VERSION);

/* TCP keepalive has proven to be vital in many deployment scenarios.
 * Without keepalive, after a device has seen a sufficiently long period of
 * idle time, packets on our "bulk data" socket may be dropped because an
 * overly "smart" network infrastructure decided that TCP session was stale.
 * Note that we don't try to use this to detect "broken" tcp sessions here,
 * these will still be handled by the DRBD effective network timeout via
 * timeout / ko-count settings.
 * We use this to try to keep "idle" TCP sessions "alive".
 * Default to send a probe every 23 seconds.
 */
#define DRBD_KEEP_IDLE	(23*HZ)
#define DRBD_KEEP_INTVL (23*HZ)
#define DRBD_KEEP_CNT	9
static unsigned int drbd_keepcnt = DRBD_KEEP_CNT;
module_param_named(keepcnt, drbd_keepcnt, uint, 0664);
MODULE_PARM_DESC(keepcnt, "see tcp(7) tcp_keepalive_probes; set TCP_KEEPCNT for data sockets; default: 9");
static unsigned int drbd_keepidle = DRBD_KEEP_IDLE;
module_param_named(keepidle, drbd_keepidle, uint, 0664);
MODULE_PARM_DESC(keepidle, "see tcp(7) tcp_keepalive_time; set TCP_KEEPIDLE for data sockets; default: 23s");
static unsigned int drbd_keepintvl = DRBD_KEEP_INTVL;
module_param_named(keepintvl, drbd_keepintvl, uint, 0664);
MODULE_PARM_DESC(keepintvtl, "see tcp(7) tcp_keepalive_intvl; set TCP_KEEPINTVL for data sockets; default: 23s");

static struct workqueue_struct *dtt_csocket_recv;

struct buffer {
	void *base;
	void *pos;
};

#define DTT_CONNECTING 1
#define DTT_DATA_READY_ARMED 2

struct drbd_tcp_transport {
	struct drbd_transport transport; /* Must be first! */
	spinlock_t control_recv_lock;
	unsigned long flags;
	struct socket *stream[2];
	struct buffer rbuf[2];
	struct timer_list control_timer;
	struct work_struct control_data_ready_work;
	void (*original_control_sk_state_change)(struct sock *sk);
	void (*original_control_sk_data_ready)(struct sock *sk);
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
static void dtt_socket_free(struct socket **sock);
static int dtt_init_listener(struct drbd_transport *transport, const struct sockaddr *addr,
			     struct net *net, struct drbd_listener *drbd_listener);
static void dtt_destroy_listener(struct drbd_listener *generic_listener);
static int dtt_prepare_connect(struct drbd_transport *transport);
static int dtt_connect(struct drbd_transport *transport);
static void dtt_finish_connect(struct drbd_transport *transport);
static int dtt_recv(struct drbd_transport *transport, enum drbd_stream stream, void **buf, size_t size, int flags);
static int dtt_recv_pages(struct drbd_transport *transport, struct drbd_page_chain_head *chain, size_t size);
static void dtt_stats(struct drbd_transport *transport, struct drbd_transport_stats *stats);
static int dtt_net_conf_change(struct drbd_transport *transport, struct net_conf *new_net_conf);
static void dtt_set_rcvtimeo(struct drbd_transport *transport, enum drbd_stream stream, long timeout);
static long dtt_get_rcvtimeo(struct drbd_transport *transport, enum drbd_stream stream);
static int dtt_send_page(struct drbd_transport *transport, enum drbd_stream, struct page *page,
		int offset, size_t size, unsigned msg_flags);
static int dtt_send_zc_bio(struct drbd_transport *, struct bio *bio);
static bool dtt_stream_ok(struct drbd_transport *transport, enum drbd_stream stream);
static bool dtt_hint(struct drbd_transport *transport, enum drbd_stream stream, enum drbd_tr_hints hint);
static void dtt_debugfs_show(struct drbd_transport *transport, struct seq_file *m);
static void dtt_update_congested(struct drbd_tcp_transport *tcp_transport);
static int dtt_add_path(struct drbd_path *path);
static bool dtt_may_remove_path(struct drbd_path *);
static void dtt_remove_path(struct drbd_path *);
static void dtt_control_timer_fn(struct timer_list *t);

static struct drbd_transport_class tcp_transport_class = {
	.name = "tcp",
	.instance_size = sizeof(struct drbd_tcp_transport),
	.path_instance_size = sizeof(struct dtt_path),
	.listener_instance_size = sizeof(struct dtt_listener),
	.ops = (struct drbd_transport_ops) {
		.init = dtt_init,
		.free = dtt_free,
		.init_listener = dtt_init_listener,
		.release_listener = dtt_destroy_listener,
		.prepare_connect = dtt_prepare_connect,
		.connect = dtt_connect,
		.finish_connect = dtt_finish_connect,
		.recv = dtt_recv,
		.recv_pages = dtt_recv_pages,
		.stats = dtt_stats,
		.net_conf_change = dtt_net_conf_change,
		.set_rcvtimeo = dtt_set_rcvtimeo,
		.get_rcvtimeo = dtt_get_rcvtimeo,
		.send_page = dtt_send_page,
		.send_zc_bio = dtt_send_zc_bio,
		.stream_ok = dtt_stream_ok,
		.hint = dtt_hint,
		.debugfs_show = dtt_debugfs_show,
		.add_path = dtt_add_path,
		.may_remove_path = dtt_may_remove_path,
		.remove_path = dtt_remove_path,
	},
	.module = THIS_MODULE,
	.list = LIST_HEAD_INIT(tcp_transport_class.list),
};

static int dtt_init(struct drbd_transport *transport)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);
	enum drbd_stream i;

	spin_lock_init(&tcp_transport->control_recv_lock);
	tcp_transport->transport.class = &tcp_transport_class;
	for (i = DATA_STREAM; i <= CONTROL_STREAM ; i++) {
		void *buffer = (void *)__get_free_page(GFP_KERNEL);
		if (!buffer)
			goto fail;
		tcp_transport->rbuf[i].base = buffer;
		tcp_transport->rbuf[i].pos = buffer;
	}
	timer_setup(&tcp_transport->control_timer, dtt_control_timer_fn, 0);

	return 0;
fail:
	free_page((unsigned long)tcp_transport->rbuf[0].base);
	return -ENOMEM;
}

static void dtt_free(struct drbd_transport *transport, enum drbd_tr_free_op free_op)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);
	enum drbd_stream i;
	struct drbd_path *drbd_path;
	/* free the socket specific stuff,
	 * mutexes are handled by caller */

	clear_bit(DTT_DATA_READY_ARMED, &tcp_transport->flags);

	if (tcp_transport->control_data_ready_work.func) {
		cancel_work_sync(&tcp_transport->control_data_ready_work);
		tcp_transport->control_data_ready_work.func = NULL;
	}

	if (tcp_transport->stream[CONTROL_STREAM] &&
	    tcp_transport->original_control_sk_state_change) {
		write_lock_bh(&tcp_transport->stream[CONTROL_STREAM]->sk->sk_callback_lock);
		tcp_transport->stream[CONTROL_STREAM]->sk->sk_state_change =
			tcp_transport->original_control_sk_state_change;
		write_unlock_bh(&tcp_transport->stream[CONTROL_STREAM]->sk->sk_callback_lock);
	}

	synchronize_rcu();
	for (i = DATA_STREAM; i <= CONTROL_STREAM; i++) {
		dtt_socket_free(&tcp_transport->stream[i]);
	}

	list_for_each_entry(drbd_path, &transport->paths, list) {
		bool was_established = test_and_clear_bit(TR_ESTABLISHED, &drbd_path->flags);

		if (free_op == CLOSE_CONNECTION && was_established)
			drbd_path_event(transport, drbd_path);
	}

	del_timer_sync(&tcp_transport->control_timer);

	if (free_op == DESTROY_TRANSPORT) {
		for (i = DATA_STREAM; i <= CONTROL_STREAM; i++) {
			free_page((unsigned long)tcp_transport->rbuf[i].base);
			tcp_transport->rbuf[i].base = NULL;
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
	union {
		struct cmsghdr cmsg;
		u8 buf[CMSG_SPACE(sizeof(u8))];
	} u;
	struct msghdr msg = {
		.msg_control = &u,
		.msg_controllen = sizeof(u),
	};
	int ret;

	flags = flags ? flags : MSG_WAITALL | MSG_NOSIGNAL;

	ret = kernel_recvmsg(socket, &msg, &iov, 1, size, flags);

	if (msg.msg_controllen != sizeof(u)) {
		u8 level, description;

		switch (tls_get_record_type(socket->sk, &u.cmsg)) {
		case 0:
			fallthrough;
		case TLS_RECORD_TYPE_DATA:
			break;
		case TLS_RECORD_TYPE_ALERT:
			tls_alert_recv(socket->sk, &msg, &level, &description);
			ret = (level == TLS_ALERT_LEVEL_FATAL) ? -EACCES : -EAGAIN;
			break;
		default:
			/* discard this record type */
			ret = -EAGAIN;
			break;
		}
	}

	return ret;
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
		size -= err;
	}
	if (unlikely(size)) {
		tr_warn(transport, "Not enough data received; missing %zu bytes\n", size);
		err = -ENODATA;
		goto fail;
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
	struct sock *sk = socket->sk;

	/* open coded SO_SNDBUF, SO_RCVBUF */
	if (snd) {
		sk->sk_sndbuf = snd;
		sk->sk_userlocks |= SOCK_SNDBUF_LOCK;
		/* Wake up sending tasks if we upped the value. */
		sk->sk_write_space(sk);
	} else {
		sk->sk_userlocks &= ~SOCK_SNDBUF_LOCK;
	}

	if (rcv) {
		sk->sk_rcvbuf = rcv;
		sk->sk_userlocks |= SOCK_RCVBUF_LOCK;
	} else {
		sk->sk_userlocks &= ~SOCK_RCVBUF_LOCK;
	}
}

static bool dtt_path_cmp_addr(struct dtt_path *path)
{
	struct drbd_path *drbd_path = &path->path;
	int addr_size;

	addr_size = min(drbd_path->my_addr_len, drbd_path->peer_addr_len);
	return memcmp(&drbd_path->my_addr, &drbd_path->peer_addr, addr_size) > 0;
}

static int dtt_try_connect(struct dtt_path *path, struct socket **ret_socket)
{
	struct drbd_transport *transport = path->path.transport;
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
	err = sock_create_kern(path->path.net, my_addr.ss_family, SOCK_STREAM, IPPROTO_TCP, &socket);
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

typedef int (*tls_hello_func)(const struct tls_handshake_args *, gfp_t);

struct tls_handshake_wait {
	struct completion done;
	int status;
};

static void tls_handshake_done(void *data, int status, key_serial_t peerid)
{
	struct tls_handshake_wait *wait = data;

	// Normalize the error to be negative: while the error _should_ be negative
	// it is not guaranteed: the netlink interface allows any u32 value, which is
	// then negated and cast to int, so who knows what will be returned.
	if (status > 0)
		status = -status;

	wait->status = status;
	complete(&wait->done);
}

static int tls_init_hello(struct socket *sock, const char *peername,
			  key_serial_t keyring, key_serial_t privkey,
			  key_serial_t certificate, tls_hello_func hello,
			  struct tls_handshake_wait *tls_wait)
{
	int err;
	struct tls_handshake_args tls_args = {
			.ta_sock = sock,
			.ta_done = tls_handshake_done,
			.ta_data = tls_wait,
			.ta_peername = peername,
			.ta_keyring = keyring,
			.ta_my_privkey = privkey,
			.ta_my_cert = certificate,
	};

	if (IS_ERR(sock_alloc_file(sock, O_NONBLOCK, NULL)))
		return -EIO;

	do {
		err = hello(&tls_args, GFP_KERNEL);
	} while (err == -EAGAIN);

	return err;
}

static int tls_wait_hello(struct tls_handshake_wait *csocket_tls_wait,
			  struct tls_handshake_wait *dsocket_tls_wait,
			  unsigned long timeout)
{
	unsigned long remaining = wait_for_completion_timeout(
		&csocket_tls_wait->done, timeout);
	if (!remaining)
		return -ETIMEDOUT;

	if (!wait_for_completion_timeout(&dsocket_tls_wait->done, remaining))
		return -ETIMEDOUT;

	if (csocket_tls_wait->status)
		return csocket_tls_wait->status;

	return dsocket_tls_wait->status;
}


static int dtt_send_first_packet(struct drbd_tcp_transport *tcp_transport, struct socket *socket,
				 enum drbd_packet cmd)
{
	struct p_header80 h;

	h.magic = cpu_to_be32(DRBD_MAGIC);
	h.command = cpu_to_be16(cmd);
	h.length = 0;

	return _dtt_send(tcp_transport, socket, &h, sizeof(h), 0);
}

/**
 * dtt_socket_free() - Free the socket
 * @socket:	pointer to the pointer to the socket.
 */
static void dtt_socket_free(struct socket **socket)
{
	if (!*socket)
		return;

	tls_handshake_cancel((*socket)->sk);
	kernel_sock_shutdown(*socket, SHUT_RDWR);

	if ((*socket)->file)
		sockfd_put((*socket));
	else
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

	if (good == 0) {
		kref_put(&(*first_path)->path.kref, drbd_destroy_path);
		*first_path = NULL;
	}

	return good == 2;
}

static struct dtt_path *dtt_wait_connect_cond(struct drbd_transport *transport)
{
	struct drbd_listener *listener;
	struct drbd_path *drbd_path;
	struct dtt_path *path = NULL;
	bool rv = false;

	rcu_read_lock();
	list_for_each_entry_rcu(drbd_path, &transport->paths, list) {
		path = container_of(drbd_path, struct dtt_path, path);
		listener = drbd_path->listener;

		spin_lock_bh(&listener->waiters_lock);
		rv = listener->pending_accepts > 0 || !list_empty(&path->sockets);
		spin_unlock_bh(&listener->waiters_lock);

		if (rv)
			break;
	}
	if (rv)
		kref_get(&path->path.kref);
	rcu_read_unlock();

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
	timeo += get_random_u32_below(2) ? timeo / 7 : -timeo / 7; /* 28.5% random jitter */

retry:
	if (path)
		kref_put(&path->path.kref, drbd_destroy_path);
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
		if (err < 0) {
			kref_put(&path->path.kref, drbd_destroy_path);
			return err;
		}

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
	if (*ret_path)
		kref_put(&(*ret_path)->path.kref, drbd_destroy_path);
	*ret_path = path;
	return 0;

retry_locked:
	spin_unlock_bh(&listener->listener.waiters_lock);
	dtt_socket_free(&s_estab);
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


static int dtt_control_tcp_input(read_descriptor_t *rd_desc, struct sk_buff *skb,
				 unsigned int offset, size_t len)
{
	struct drbd_transport *transport = rd_desc->arg.data;
	unsigned int avail, consumed = 0;
	struct skb_seq_state seq;

	skb_prepare_seq_read(skb, offset, offset + len, &seq);
	do {
		struct drbd_const_buffer buffer;

		/*
		 * skb_seq_read() returns the length of the block assigned to buffer. This might
		 * be more than is actually ready, so we ensure we only mark as available what
		 * is ready.
		 */
		avail = skb_seq_read(consumed, &buffer.buffer, &seq);
		if (!avail)
			break;
		buffer.avail = min_t(unsigned int, avail, len - consumed);
		consumed += buffer.avail;
		drbd_control_data_ready(transport, &buffer);
	} while (consumed < len);
	skb_abort_seq_read(&seq);

	return consumed;
}

static void dtt_control_data_ready_work(struct work_struct *item)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(item, struct drbd_tcp_transport, control_data_ready_work);
	struct socket *csocket = tcp_transport->stream[CONTROL_STREAM];
	struct drbd_const_buffer drbd_buffer;
	int n;

	while (true) {
		n = dtt_recv_short(csocket, tcp_transport->rbuf[CONTROL_STREAM].base, PAGE_SIZE,
				   MSG_DONTWAIT | MSG_NOSIGNAL);
		if (n <= 0)
			break;

		drbd_buffer.buffer = tcp_transport->rbuf[CONTROL_STREAM].base;
		drbd_buffer.avail = n;
		drbd_control_data_ready(&tcp_transport->transport, &drbd_buffer);
	}
}

static void dtt_control_data_ready(struct sock *sock)
{
	struct drbd_transport *transport = sock->sk_user_data;
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);

	read_descriptor_t rd_desc = {
		.count = 1,
		.arg = { .data = transport },
	};

	if (!test_bit(DTT_DATA_READY_ARMED, &tcp_transport->flags)
	    && tcp_transport->original_control_sk_data_ready)
		return tcp_transport->original_control_sk_data_ready(sock);

	/* We have two different paths depending on if TLS is enabled or not.
	 * If TLS is enabled, we can't use read_sock, firstly because it's not implemented for the
	 * TLS protocol on most kernels, secondly the implementation that does exist is not safe
	 * to call from SOFTIRQ context. Instead, we schedule a work and increment the counter of
	 * "pending" ready events.
	 *
	 * In normal TCP mode, we can simply use tcp_read_sock, as that is safe to call from SOFTIRQ
	 * contexts.
	 */
	mod_timer(&tcp_transport->control_timer, jiffies + sock->sk_rcvtimeo);
	if (tcp_transport->control_data_ready_work.func) {
		queue_work(dtt_csocket_recv, &tcp_transport->control_data_ready_work);
	} else {
		spin_lock_bh(&tcp_transport->control_recv_lock);
		tcp_read_sock(sock, &rd_desc, dtt_control_tcp_input);
		spin_unlock_bh(&tcp_transport->control_recv_lock);
	}
}

static void dtt_control_state_change(struct sock *sock)
{
	struct drbd_transport *transport = sock->sk_user_data;
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);

	switch (sock->sk_state) {
	case TCP_FIN_WAIT1:
	case TCP_CLOSE_WAIT:
	case TCP_CLOSE:
	case TCP_LAST_ACK:
	case TCP_CLOSING:
		drbd_control_event(transport, CLOSED_BY_PEER);
		break;
	default:
		tr_warn(transport, "unhandled state %d\n", sock->sk_state);
	}

	tcp_transport->original_control_sk_state_change(sock);
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

static void dtt_control_timer_fn(struct timer_list *t)
{
	struct drbd_tcp_transport *tcp_transport = from_timer(tcp_transport, t, control_timer);
	struct drbd_transport *transport = &tcp_transport->transport;

	drbd_control_event(transport, TIMEOUT);
}

static void dtt_destroy_listener(struct drbd_listener *generic_listener)
{
	struct dtt_listener *listener =
		container_of(generic_listener, struct dtt_listener, listener);

	if (!listener->s_listen)
		return;
	unregister_state_change(listener->s_listen->sk, listener);
	sock_release(listener->s_listen);
}

static int dtt_init_listener(struct drbd_transport *transport,
			     const struct sockaddr *addr,
			     struct net *net,
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

	err = sock_create_kern(net, my_addr.ss_family, SOCK_STREAM, IPPROTO_TCP, &s_listen);
	if (err < 0) {
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
		dtt_socket_free(&socket_c->socket);
		kfree(socket_c);
	}
}

static void dtt_finish_connect(struct drbd_transport *transport)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);
	struct dtt_path *path;

	clear_bit(DTT_CONNECTING, &tcp_transport->flags);

	list_for_each_entry(path, &transport->paths, path.list) {
		drbd_put_listener(&path->path);
		dtt_cleanup_accepted_sockets(path);
	}
}

static struct dtt_path *dtt_next_path(struct dtt_path *path, struct drbd_transport *transport)
{
	struct drbd_path *drbd_path;

	drbd_path = __drbd_next_path_ref(path ? &path->path : NULL, transport);

	/* Loop when we reach the end. */
	if (!drbd_path)
		drbd_path = __drbd_next_path_ref(NULL, transport);

	return drbd_path ? container_of(drbd_path, struct dtt_path, path) : NULL;
}

static int dtt_prepare_connect(struct drbd_transport *transport)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);
	struct dtt_path *path;
	struct drbd_path *drbd_path;

	list_for_each_entry(path, &transport->paths, path.list)
		dtt_cleanup_accepted_sockets(path);

	set_bit(DTT_CONNECTING, &tcp_transport->flags);

	list_for_each_entry(drbd_path, &transport->paths, list) {
		if (!drbd_path->listener) {
			int err = drbd_get_listener(drbd_path);

			if (err)
				return err;
		}
	}

	return 0;
}

static int dtt_connect(struct drbd_transport *transport)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);
	struct dtt_path *connect_to_path, *first_path = NULL;
	struct socket *dsocket, *csocket;
	struct net_conf *nc;
	bool tls, dsocket_is_server = false, csocket_is_server = false;
	char peername[64];
	key_serial_t tls_keyring, tls_privkey, tls_certificate;
	int timeout, err;
	bool ok;

	dsocket = NULL;
	csocket = NULL;

	connect_to_path = dtt_next_path(NULL, transport);
	if (!connect_to_path) {
		err = -EDESTADDRREQ;
		goto out;
	}

	do {
		struct socket *s = NULL;

		err = dtt_try_connect(connect_to_path, &s);
		if (err < 0 && err != -EAGAIN)
			goto out_release_sockets;

		if (s) {
			bool use_for_data;

			if (first_path) {
				if (first_path != connect_to_path) {
					tr_info(transport, "initial paths crossed A - fail over\n");
					dtt_socket_free(&dsocket);
					dtt_socket_free(&csocket);
				}

				kref_put(&first_path->path.kref, drbd_destroy_path);
				first_path = NULL;
			}

			kref_get(&connect_to_path->path.kref);
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

			if (!use_for_data)
				clear_bit(RESOLVE_CONFLICTS, &transport->flags);

			err = dtt_send_first_packet(tcp_transport,
						    s,
						    use_for_data ? P_INITIAL_DATA : P_INITIAL_META);

			if (err < 0) {
				tr_warn(transport, "Error sending initial packet: %d\n", err);
				dtt_socket_free(&s);
			} else if (use_for_data) {
				dsocket = s;
				dsocket_is_server = false;
			} else {
				csocket = s;
				csocket_is_server = false;
			}
		} else if (!first_path) {
			connect_to_path = dtt_next_path(connect_to_path, transport);

			/*
			 * The final path should not be removed while
			 * connecting, but handle the case for robustness.
			 */
			err = -EDESTADDRREQ;
			if (!connect_to_path)
				goto out_release_sockets;
		}

		if (dtt_connection_established(transport, &dsocket, &csocket, &first_path))
			break;

retry:
		s = NULL;
		err = dtt_wait_for_connect(transport, connect_to_path->path.listener, &s, &connect_to_path);
		if (err < 0 && err != -EAGAIN)
			goto out_release_sockets;

		if (s) {
			int fp = dtt_receive_first_packet(tcp_transport, s);

			if (first_path) {
				if (first_path != connect_to_path) {
					tr_info(transport, "initial paths crossed P - fail over\n");
					dtt_socket_free(&dsocket);
					dtt_socket_free(&csocket);
				}

				kref_put(&first_path->path.kref, drbd_destroy_path);
				first_path = NULL;
			}

			kref_get(&connect_to_path->path.kref);
			first_path = connect_to_path;

			dtt_socket_ok_or_free(&dsocket);
			dtt_socket_ok_or_free(&csocket);
			switch (fp) {
			case P_INITIAL_DATA:
				if (dsocket) {
					tr_warn(transport, "initial packet S crossed\n");
					dtt_socket_free(&dsocket);
					dsocket = s;
					dsocket_is_server = true;
					goto randomize;
				}
				dsocket = s;
				dsocket_is_server = true;
				break;
			case P_INITIAL_META:
				set_bit(RESOLVE_CONFLICTS, &transport->flags);
				if (csocket) {
					tr_warn(transport, "initial packet M crossed\n");
					dtt_socket_free(&csocket);
					csocket = s;
					csocket_is_server = true;
					goto randomize;
				}
				csocket = s;
				csocket_is_server = true;
				break;
			default:
				tr_warn(transport, "Error receiving initial packet: %d\n", fp);
				dtt_socket_free(&s);
randomize:
				if (get_random_u32_below(2))
					goto retry;
			}
		}

		if (drbd_should_abort_listening(transport))
			goto out_eagain;

		ok = dtt_connection_established(transport, &dsocket, &csocket, &first_path);
	} while (!ok);

	rcu_read_lock();
	nc = rcu_dereference(transport->net_conf);
	timeout = nc->timeout * HZ / 10;
	tls = nc->tls;
	memcpy(peername, nc->name, 64);
	tls_keyring = nc->tls_keyring;
	tls_privkey = nc->tls_privkey;
	tls_certificate = nc->tls_certificate;
	rcu_read_unlock();

	write_lock_bh(&csocket->sk->sk_callback_lock);
	clear_bit(DTT_DATA_READY_ARMED, &tcp_transport->flags);
	tcp_transport->original_control_sk_data_ready = csocket->sk->sk_data_ready;
	csocket->sk->sk_user_data = transport;
	csocket->sk->sk_data_ready = dtt_control_data_ready;
	write_unlock_bh(&csocket->sk->sk_callback_lock);

	if (tls) {
		struct tls_handshake_wait csocket_tls_wait = {
			.done = COMPLETION_INITIALIZER_ONSTACK(csocket_tls_wait.done),
		};
		struct tls_handshake_wait dsocket_tls_wait = {
			.done = COMPLETION_INITIALIZER_ONSTACK(dsocket_tls_wait.done),
		};

		err = tls_init_hello(
			csocket, peername, tls_keyring, tls_privkey, tls_certificate,
			csocket_is_server ? tls_server_hello_x509 : tls_client_hello_x509,
			&csocket_tls_wait);
		if (err < 0) {
			tr_warn(transport, "Error from control socket tls handshake: %d\n", err);
			goto out_release_sockets;
		}

		err = tls_init_hello(
			dsocket, peername, tls_keyring, tls_privkey, tls_certificate,
			dsocket_is_server ? tls_server_hello_x509 : tls_client_hello_x509,
			&dsocket_tls_wait);
		if (err < 0) {
			tr_warn(transport, "Error from data socket tls handshake: %d\n", err);
			goto out_release_sockets;
		}

		err = tls_wait_hello(&csocket_tls_wait, &dsocket_tls_wait, timeout);
		if (err < 0) {
			tr_warn(transport, "Error from tls handshake: %d\n", err);
			goto out_release_sockets;
		}

		INIT_WORK(&tcp_transport->control_data_ready_work, dtt_control_data_ready_work);
	}

	TR_ASSERT(transport, first_path == connect_to_path);
	set_bit(TR_ESTABLISHED, &connect_to_path->path.flags);
	drbd_path_event(transport, &connect_to_path->path);

	dsocket->sk->sk_reuse = SK_CAN_REUSE; /* SO_REUSEADDR */
	csocket->sk->sk_reuse = SK_CAN_REUSE; /* SO_REUSEADDR */

	/* We are a block device, we are in the write-out path,
	 * we may need memory to facilitate memory reclaim
	 */
	dsocket->sk->sk_allocation = GFP_ATOMIC;
	csocket->sk->sk_allocation = GFP_ATOMIC;

	dsocket->sk->sk_use_task_frag = false;
	csocket->sk->sk_use_task_frag = false;

	sk_set_memalloc(dsocket->sk);
	sk_set_memalloc(csocket->sk);

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

	dsocket->sk->sk_sndtimeo = timeout;
	csocket->sk->sk_sndtimeo = timeout;

	sock_set_keepalive(dsocket->sk);

	if (drbd_keepidle)
		tcp_sock_set_keepidle(dsocket->sk, drbd_keepidle);
	if (drbd_keepcnt)
		tcp_sock_set_keepcnt(dsocket->sk, drbd_keepcnt);
	if (drbd_keepintvl)
		tcp_sock_set_keepintvl(dsocket->sk, drbd_keepintvl);

	write_lock_bh(&csocket->sk->sk_callback_lock);
	tcp_transport->original_control_sk_state_change = csocket->sk->sk_state_change;
	csocket->sk->sk_state_change = dtt_control_state_change;
	set_bit(DTT_DATA_READY_ARMED, &tcp_transport->flags);
	write_unlock_bh(&csocket->sk->sk_callback_lock);

	err = 0;
	goto out;

out_eagain:
	err = -EAGAIN;

out_release_sockets:
	dtt_socket_free(&dsocket);
	dtt_socket_free(&csocket);

out:
	if (first_path)
		kref_put(&first_path->path.kref, drbd_destroy_path);
	if (connect_to_path)
		kref_put(&connect_to_path->path.kref, drbd_destroy_path);

	return err;
}

static int dtt_net_conf_change(struct drbd_transport *transport, struct net_conf *new_net_conf)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);
	struct net_conf *old_net_conf;
	struct socket *data_socket = tcp_transport->stream[DATA_STREAM];
	struct socket *control_socket = tcp_transport->stream[CONTROL_STREAM];

	rcu_read_lock();
	old_net_conf = rcu_dereference(transport->net_conf);
	rcu_read_unlock();

	if (old_net_conf && old_net_conf->tls != new_net_conf->tls &&
	    (data_socket || control_socket)) {
		tr_warn(transport, "cannot switch tls (%s -> %s) while connected\n",
			old_net_conf->tls ? "yes" : "no", new_net_conf->tls ? "yes" : "no");
		return -EINVAL;
	}

	if (data_socket) {
		dtt_setbufsize(data_socket, new_net_conf->sndbuf_size, new_net_conf->rcvbuf_size);
	}

	if (control_socket) {
		dtt_setbufsize(control_socket, new_net_conf->sndbuf_size, new_net_conf->rcvbuf_size);
	}

	return 0;
}

static void dtt_set_rcvtimeo(struct drbd_transport *transport, enum drbd_stream stream, long timeout)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);
	struct socket *socket = tcp_transport->stream[stream];

	if (!socket)
		return;

	socket->sk->sk_rcvtimeo = timeout;

	if (stream == CONTROL_STREAM)
		mod_timer(&tcp_transport->control_timer, jiffies + timeout);

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
	struct msghdr msg = { .msg_flags = msg_flags | MSG_NOSIGNAL | MSG_SPLICE_PAGES };
	struct bio_vec bvec;
	int len = size;
	int err = -EIO;

	if (!socket)
		return -ENOTCONN;

	dtt_update_congested(tcp_transport);
	do {
		int sent;

		bvec_set_page(&bvec, page, len, offset);
		iov_iter_bvec(&msg.msg_iter, ITER_SOURCE, &bvec, 1, len);

		sent = sock_sendmsg(socket, &msg);
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

static int dtt_add_path(struct drbd_path *drbd_path)
{
	struct drbd_transport *transport = drbd_path->transport;
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);
	struct dtt_path *path = container_of(drbd_path, struct dtt_path, path);

	clear_bit(TR_ESTABLISHED, &drbd_path->flags);
	INIT_LIST_HEAD(&path->sockets);

	if (!test_bit(DTT_CONNECTING, &tcp_transport->flags))
		return 0;

	return drbd_get_listener(drbd_path);
}

static bool dtt_may_remove_path(struct drbd_path *drbd_path)
{
	return !test_bit(TR_ESTABLISHED, &drbd_path->flags);
}

static void dtt_remove_path(struct drbd_path *drbd_path)
{
	drbd_put_listener(drbd_path);
}

static int __init dtt_initialize(void)
{
	dtt_csocket_recv = alloc_workqueue("dtt_csocket_recv",
					   WQ_UNBOUND | WQ_MEM_RECLAIM | WQ_HIGHPRI, 0);
	if (!dtt_csocket_recv)
		return -ENOMEM;
	return drbd_register_transport_class(&tcp_transport_class,
					     DRBD_TRANSPORT_API_VERSION,
					     sizeof(struct drbd_transport));
}

static void __exit dtt_cleanup(void)
{
	destroy_workqueue(dtt_csocket_recv);
	drbd_unregister_transport_class(&tcp_transport_class);
}

module_init(dtt_initialize)
module_exit(dtt_cleanup)
