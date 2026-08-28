/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Context and outcome of one DRBD netlink configuration command.
 *
 * The command implementations are independent of the wire format: they
 * receive the identity of the object to act on and report back a result
 * code plus a few informational messages. Translating that into the
 * bytes of a particular netlink dialect is the job of the per-dialect
 * pre_doit/post_doit handlers.
 */
#ifndef __DRBD_NL_H
#define __DRBD_NL_H

#include <linux/compiler.h>
#include <linux/drbd_nl_types.h>

struct drbd_device;
struct drbd_resource;
struct drbd_connection;
struct drbd_peer_device;
struct sk_buff;
struct drbd_genlmsghdr;
struct net;

/* per-message cap, same as drbd_msg_sprintf_info()'s reserve */
#define DRBD_ADM_MSG_MAX	256
/*
 * Total info text per request; a strict superset of what the legacy
 * NLMSG_GOODSIZE reply could carry (that is capped at
 * SKB_WITH_OVERHEAD(8192UL) on every page size).
 */
#define DRBD_ADM_MSG_BUF	8192

struct drbd_adm_ctx {
	/* identity, filled from the request by the dialect's pre_doit */
	unsigned int minor;
	unsigned int volume;
#define VOLUME_UNSPECIFIED		(-1U)
	unsigned int peer_node_id;
#define PEER_NODE_ID_UNSPECIFIED	(-1U)
	const char *resource_name;	/* points into the request; limited lifetime */
	struct net *net;
	bool set_defaults;

	/* resolved by drbd_adm_ctx_resolve() */
	struct drbd_device *device;
	struct drbd_resource *resource;
	struct drbd_connection *connection;
	struct drbd_peer_device *peer_device;

	/* outcome, serialized by the dialect's post_doit */
	int result;			/* NO_ERROR, ERR_*, SS_* or -errno */
	unsigned int msg_len;		/* bytes used in msg[] */
	/*
	 * NUL-separated info messages, in order. Each message is truncated
	 * at DRBD_ADM_MSG_MAX; a message that does not fit into what is
	 * left of the buffer is dropped, exactly as an over-full reply skb
	 * dropped it before.
	 */
	char msg[DRBD_ADM_MSG_BUF];

	/* legacy wire state -- moves into the adapter in Task 3 */
	struct sk_buff *reply_skb;
	struct drbd_genlmsghdr *reply_dh;
};

__printf(2, 3) void drbd_adm_msg(struct drbd_adm_ctx *ctx, const char *fmt, ...);

#endif /* __DRBD_NL_H */
