// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026, LINBIT HA-Solutions GmbH.
 */

/*
 * The "drbd2" generic netlink family: everything that knows about the
 * bytes on the wire of that dialect. The command implementations
 * themselves live in drbd_nl.c and only ever see a struct drbd_adm_ctx.
 *
 * Unlike the legacy "drbd" family, drbd2 has no fixed message header and
 * no place to carry a drbd_ret_code, so the outcome of a request is split
 * in two, as the specification prescribes:
 *
 *   - A state change reports its drbd_state_rv in the state-result
 *     attribute of the reply, together with the accumulated info messages
 *     in message. A refused state change is data, not a transport error.
 *   - Everything that failed for a configuration reason (the ERR_* codes)
 *     becomes an errno plus a description in the extended ACK, and no
 *     reply is sent at all.
 *
 * The description in the extended ACK is the command's own account of the
 * failure where it left one -- the first of the info messages the core
 * collected, formatted into the ACK's buffer so that it outlives the
 * command context -- and the generic text of the ERR_* code otherwise.
 * Failures that are about one attribute of the request also name that
 * attribute, the way the netlink policy checks do. Further info messages
 * are lost on the errno path; the reply of a completed command carries
 * them all.
 */

#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt

#include <linux/slab.h>
#include <linux/drbd.h>
#include <linux/drbd2_nl_gen.h>
#include <net/genetlink.h>
#include <net/sock.h>

#include "drbd_int.h"
#include "drbd_nl.h"

static const struct drbd_nl_dialect drbd2_dialect;

/* Per-request state of the drbd2 dialect; hangs off drbd_adm_ctx.req. */
struct drbd2_req {
	struct genl_info *info;
	struct sk_buff *reply_skb;
	void *reply_hdr;
	/* the command filled the reply itself; do not add state-result */
	bool payload_reply;
};

/* One allocation for both, so that pre_doit zeroes the context only once. */
struct drbd2_ctx {
	struct drbd_adm_ctx ctx;
	struct drbd2_req req;
};

static inline struct drbd2_req *drbd2_req(struct drbd_adm_ctx *ctx)
{
	return ctx->req;
}

/*
 * drbd2 numbers its attributes from 1, so attribute 0 is free to serve as
 * the padding attribute of the 64 bit values, the same way the legacy
 * marshalling code uses it.
 */
#define DRBD2_A_PAD	0

static int drbd2_put_u64(struct sk_buff *skb, int attrtype, u64 value)
{
	return nla_put_u64_64bit(skb, attrtype, value, DRBD2_A_PAD);
}

/*
 * The internal string buffers carry an explicit length and are
 * NUL-terminated unless they are completely full; emit them including
 * that terminating NUL, as the drbd2 policies expect.
 */
static int drbd2_put_str(struct sk_buff *skb, int attrtype,
			 const char *val, u32 len, u32 size)
{
	return nla_put(skb, attrtype, min_t(u32, size, len + (len < size)), val);
}

/* A socket address as the address nest of "attrtype". */
static int drbd2_put_address(struct sk_buff *skb, int attrtype,
			     const struct sockaddr_storage *addr)
{
	struct nlattr *nla = nla_nest_start(skb, attrtype);

	if (!nla)
		return -EMSGSIZE;
	if (nla_put_u16(skb, DRBD2_A_ADDRESS_FAMILY, addr->ss_family))
		goto fail;
	switch (addr->ss_family) {
	case AF_INET: {
		const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;

		if (nla_put_be16(skb, DRBD2_A_ADDRESS_PORT, sin->sin_port) ||
		    nla_put_be32(skb, DRBD2_A_ADDRESS_IPV4, sin->sin_addr.s_addr))
			goto fail;
		break;
	}
	case AF_INET6: {
		const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)addr;

		if (nla_put_be16(skb, DRBD2_A_ADDRESS_PORT, sin6->sin6_port) ||
		    nla_put(skb, DRBD2_A_ADDRESS_IPV6,
			    sizeof(sin6->sin6_addr), &sin6->sin6_addr))
			goto fail;
		break;
	}
	default:
		/* the family alone is all this dialect can say about it */
		break;
	}
	nla_nest_end(skb, nla);
	return 0;

fail:
	nla_nest_cancel(skb, nla);
	return -EMSGSIZE;
}

/*
 * The reverse: one address nest into the sockaddr_storage the transports
 * work with. Returns -ENOMSG if the nest does not describe an address of
 * a family this dialect knows.
 */
static int drbd2_get_address(const struct nlattr *nla, char *dst, __u32 *dst_len)
{
	struct nlattr *tb[DRBD2_A_ADDRESS_IPV6 + 1];
	int err;

	err = nla_parse_nested(tb, DRBD2_A_ADDRESS_IPV6, nla,
			       drbd2_address_nl_policy, NULL);
	if (err)
		return err;
	if (!tb[DRBD2_A_ADDRESS_FAMILY] || !tb[DRBD2_A_ADDRESS_PORT])
		return -ENOMSG;

	switch (nla_get_u16(tb[DRBD2_A_ADDRESS_FAMILY])) {
	case AF_INET: {
		struct sockaddr_in sin = { .sin_family = AF_INET };

		if (!tb[DRBD2_A_ADDRESS_IPV4])
			return -ENOMSG;
		sin.sin_port = nla_get_be16(tb[DRBD2_A_ADDRESS_PORT]);
		sin.sin_addr.s_addr = nla_get_be32(tb[DRBD2_A_ADDRESS_IPV4]);
		memcpy(dst, &sin, sizeof(sin));
		*dst_len = sizeof(sin);
		return 0;
	}
	case AF_INET6: {
		struct sockaddr_in6 sin6 = { .sin6_family = AF_INET6 };

		if (!tb[DRBD2_A_ADDRESS_IPV6])
			return -ENOMSG;
		sin6.sin6_port = nla_get_be16(tb[DRBD2_A_ADDRESS_PORT]);
		memcpy(&sin6.sin6_addr, nla_data(tb[DRBD2_A_ADDRESS_IPV6]),
		       sizeof(sin6.sin6_addr));
		memcpy(dst, &sin6, sizeof(sin6));
		*dst_len = sizeof(sin6);
		return 0;
	}
	}
	return -ENOMSG;
}

static int drbd2_genl_multicast_events(struct sk_buff *skb)
{
	return genlmsg_multicast_allns(&drbd2_nl_family, skb, 0,
				       DRBD2_NLGRP_EVENTS);
}

/*
 * The ERR_* codes of the command core translated into what a modern
 * netlink family reports: an errno and a description for the extended
 * ACK. The texts are the ones drbdsetup prints for the legacy family.
 */
static const struct {
	int err;
	const char *msg;
} drbd2_error_map[AFTER_LAST_ERR_CODE] = {
	[ERR_LOCAL_ADDR] = { -EADDRINUSE, "local address(port) already in use" },
	[ERR_PEER_ADDR] = { -EADDRINUSE, "remote address(port) already in use" },
	[ERR_OPEN_DISK] = { -ENOENT, "can not open backing device" },
	[ERR_OPEN_MD_DISK] = { -ENOENT, "can not open meta device" },
	[ERR_DISK_NOT_BDEV] = { -ENOTBLK, "lower device is not a block device" },
	[ERR_MD_NOT_BDEV] = { -ENOTBLK, "meta device is not a block device" },
	[ERR_DISK_TOO_SMALL] = { -ENOSPC, "lower device smaller than the requested size" },
	[ERR_MD_DISK_TOO_SMALL] = { -ENOSPC, "meta device too small" },
	[ERR_BDCLAIM_DISK] = { -EBUSY, "lower device is already claimed" },
	[ERR_BDCLAIM_MD_DISK] = { -EBUSY, "meta device is already claimed" },
	[ERR_MD_IDX_INVALID] = { -EINVAL,
		"lower device / meta device / index combination invalid" },
	[ERR_IO_MD_DISK] = { -EIO, "I/O error during initial access to meta-data" },
	[ERR_MD_INVALID] = { -EINVAL, "no valid meta-data signature found" },
	[ERR_AUTH_ALG] = { -EINVAL, "cram-hmac-alg not known to the kernel" },
	[ERR_AUTH_ALG_ND] = { -EINVAL, "cram-hmac-alg is not a digest" },
	[ERR_NOMEM] = { -ENOMEM, "out of memory" },
	[ERR_DISCARD_IMPOSSIBLE] = { -EINVAL, "discard-my-data not allowed when primary" },
	[ERR_DISK_CONFIGURED] = { -EEXIST, "device is attached to a disk" },
	[ERR_NET_CONFIGURED] = { -EEXIST, "connection has a net-config" },
	[ERR_MANDATORY_TAG] = { -EINVAL, "invalid or missing attribute" },
	[ERR_MINOR_INVALID] = { -ENOENT, "device minor not allocated" },
	[ERR_INTR] = { -EINTR, "interrupted by signal" },
	[ERR_RESIZE_RESYNC] = { -EBUSY, "resize not allowed during resync" },
	[ERR_NO_PRIMARY] = { -EINVAL, "need one primary node to resize" },
	[ERR_RESYNC_AFTER] = { -EINVAL, "the resync-after minor number is invalid" },
	[ERR_RESYNC_AFTER_CYCLE] = { -EINVAL, "this would cause a resync-after dependency cycle" },
	[ERR_PAUSE_IS_SET] = { -EALREADY, "sync-pause flag is already set" },
	[ERR_PAUSE_IS_CLEAR] = { -EALREADY, "sync-pause flag is already cleared" },
	[ERR_PACKET_NR] = { -EPROTO, "kernel does not know how to handle this request" },
	[ERR_NO_DISK] = { -ENODEV, "device does not have a disk-config" },
	[ERR_NOT_PROTO_C] = { -EINVAL, "protocol C required" },
	[ERR_NOMEM_BITMAP] = { -ENOMEM, "out of memory for the bitmap" },
	[ERR_INTEGRITY_ALG] = { -EINVAL, "data-integrity-alg not known to the kernel" },
	[ERR_INTEGRITY_ALG_ND] = { -EINVAL, "data-integrity-alg is not a digest" },
	[ERR_CPU_MASK_PARSE] = { -EINVAL, "invalid cpu-mask" },
	[ERR_CSUMS_ALG] = { -EINVAL, "csums-alg not known to the kernel" },
	[ERR_CSUMS_ALG_ND] = { -EINVAL, "csums-alg is not a digest" },
	[ERR_VERIFY_ALG] = { -EINVAL, "verify-alg not known to the kernel" },
	[ERR_VERIFY_ALG_ND] = { -EINVAL, "verify-alg is not a digest" },
	[ERR_CSUMS_RESYNC_RUNNING] = { -EBUSY,
		"can not change csums-alg while resync is in progress" },
	[ERR_VERIFY_RUNNING] = { -EBUSY, "can not change verify-alg while online verify runs" },
	[ERR_DATA_NOT_CURRENT] = { -EINVAL, "can only attach to the data we lost last" },
	[ERR_CONNECTED] = { -EBUSY, "need to be standalone" },
	[ERR_PERM] = { -EPERM, "permission denied" },
	[ERR_NEED_APV_93] = { -EOPNOTSUPP, "protocol version 93 required for assume-clean" },
	[ERR_STONITH_AND_PROT_A] = { -EINVAL,
		"fencing resource-and-stonith needs protocol B or C" },
	[ERR_CONG_NOT_PROTO_A] = { -EINVAL, "on-congestion pull-ahead needs protocol A" },
	[ERR_PIC_AFTER_DEP] = { -EALREADY, "sync-pause is cleared, but a dependency is paused" },
	[ERR_PIC_PEER_DEP] = { -EALREADY, "sync-pause is cleared, but the peer paused" },
	[ERR_RES_NOT_KNOWN] = { -ENOENT, "unknown resource" },
	[ERR_RES_IN_USE] = { -EBUSY, "resource still in use" },
	[ERR_MINOR_CONFIGURED] = { -EBUSY, "minor still configured" },
	[ERR_MINOR_OR_VOLUME_EXISTS] = { -EEXIST, "minor or volume exists already" },
	[ERR_INVALID_REQUEST] = { -EINVAL, "invalid configuration request" },
	[ERR_NEED_APV_100] = { -EOPNOTSUPP, "protocol version 100 required" },
	[ERR_NEED_ALLOW_TWO_PRI] = { -EINVAL, "can not clear allow-two-primaries now" },
	[ERR_MD_UNCLEAN] = { -EINVAL, "unclean meta-data found" },
	[ERR_MD_LAYOUT_CONNECTED] = { -EBUSY, "online meta-data layout change needs a connection" },
	[ERR_MD_LAYOUT_TOO_BIG] = { -ENOSPC, "resulting activity log area too big" },
	[ERR_MD_LAYOUT_TOO_SMALL] = { -ENOSPC, "resulting activity log area too small" },
	[ERR_MD_LAYOUT_NO_FIT] = { -ENOSPC, "resulting activity log does not fit the meta-data" },
	[ERR_IMPLICIT_SHRINK] = { -EINVAL, "implicit device shrinking not allowed" },
	[ERR_INVALID_PEER_NODE_ID] = { -EINVAL, "invalid peer-node-id" },
	[ERR_CREATE_TRANSPORT] = { -ENOENT, "failed to create transport" },
	[ERR_LOCAL_AND_PEER_ADDR] = { -EADDRINUSE,
		"combination of local and remote address already in use" },
	[ERR_ALREADY_EXISTS] = { -EEXIST, "already exists" },
	[ERR_APV_TOO_LOW] = { -EOPNOTSUPP, "a higher DRBD protocol level is required" },
	[ERR_PATH_COLLISION] = { -EEXIST, "path collides with an existing path" },
};

static bool drbd2_is_ret_code(int result)
{
	return result > NO_ERROR && result < AFTER_LAST_ERR_CODE;
}

/* The errno an ERR_* code becomes on the wire. */
static int drbd2_errno(int result)
{
	if (result == NO_ERROR)
		return 0;
	if (!drbd2_is_ret_code(result))
		return result < 0 ? result : -EINVAL;
	return drbd2_error_map[result].err ? : -EINVAL;
}

/*
 * The request attribute a failure is about, for the codes that are
 * specific to one: the top level nest and the attribute within it.
 */
static const struct {
	u16 nest;
	u16 attr;
} drbd2_error_attr[AFTER_LAST_ERR_CODE] = {
	[ERR_OPEN_DISK]		= { DRBD2_A_DISK_CONF, DRBD2_A_DISK_CONF_BACKING_DEV },
	[ERR_DISK_NOT_BDEV]	= { DRBD2_A_DISK_CONF, DRBD2_A_DISK_CONF_BACKING_DEV },
	[ERR_BDCLAIM_DISK]	= { DRBD2_A_DISK_CONF, DRBD2_A_DISK_CONF_BACKING_DEV },
	[ERR_DISK_TOO_SMALL]	= { DRBD2_A_DISK_CONF, DRBD2_A_DISK_CONF_BACKING_DEV },
	[ERR_OPEN_MD_DISK]	= { DRBD2_A_DISK_CONF, DRBD2_A_DISK_CONF_META_DEV },
	[ERR_MD_NOT_BDEV]	= { DRBD2_A_DISK_CONF, DRBD2_A_DISK_CONF_META_DEV },
	[ERR_BDCLAIM_MD_DISK]	= { DRBD2_A_DISK_CONF, DRBD2_A_DISK_CONF_META_DEV },
	[ERR_MD_DISK_TOO_SMALL]	= { DRBD2_A_DISK_CONF, DRBD2_A_DISK_CONF_META_DEV },
	[ERR_MD_IDX_INVALID]	= { DRBD2_A_DISK_CONF, DRBD2_A_DISK_CONF_META_DEV_IDX },
	[ERR_RESYNC_AFTER]	= { DRBD2_A_DISK_CONF, DRBD2_A_DISK_CONF_RESYNC_AFTER },
	[ERR_RESYNC_AFTER_CYCLE] = { DRBD2_A_DISK_CONF, DRBD2_A_DISK_CONF_RESYNC_AFTER },
	[ERR_CPU_MASK_PARSE]	= { DRBD2_A_RESOURCE_OPTS, DRBD2_A_RESOURCE_OPTS_CPU_MASK },
	[ERR_AUTH_ALG]		= { DRBD2_A_NET_CONF, DRBD2_A_NET_CONF_CRAM_HMAC_ALG },
	[ERR_AUTH_ALG_ND]	= { DRBD2_A_NET_CONF, DRBD2_A_NET_CONF_CRAM_HMAC_ALG },
	[ERR_INTEGRITY_ALG]	= { DRBD2_A_NET_CONF, DRBD2_A_NET_CONF_INTEGRITY_ALG },
	[ERR_INTEGRITY_ALG_ND]	= { DRBD2_A_NET_CONF, DRBD2_A_NET_CONF_INTEGRITY_ALG },
	[ERR_VERIFY_ALG]	= { DRBD2_A_NET_CONF, DRBD2_A_NET_CONF_VERIFY_ALG },
	[ERR_VERIFY_ALG_ND]	= { DRBD2_A_NET_CONF, DRBD2_A_NET_CONF_VERIFY_ALG },
	[ERR_VERIFY_RUNNING]	= { DRBD2_A_NET_CONF, DRBD2_A_NET_CONF_VERIFY_ALG },
	[ERR_CSUMS_ALG]		= { DRBD2_A_NET_CONF, DRBD2_A_NET_CONF_CSUMS_ALG },
	[ERR_CSUMS_ALG_ND]	= { DRBD2_A_NET_CONF, DRBD2_A_NET_CONF_CSUMS_ALG },
	[ERR_CSUMS_RESYNC_RUNNING] = { DRBD2_A_NET_CONF, DRBD2_A_NET_CONF_CSUMS_ALG },
	[ERR_STONITH_AND_PROT_A] = { DRBD2_A_NET_CONF, DRBD2_A_NET_CONF_FENCING },
	[ERR_CONG_NOT_PROTO_A]	= { DRBD2_A_NET_CONF, DRBD2_A_NET_CONF_ON_CONGESTION },
	[ERR_INVALID_PEER_NODE_ID] = { DRBD2_A_CONTEXT, DRBD2_A_CONTEXT_PEER_NODE_ID },
};

/*
 * Describe a failed command in the extended ACK: its own first info
 * message if it left one, the generic text of its ERR_* code otherwise,
 * and the request attribute the failure is about if there is one.
 */
static void drbd2_set_extack(struct genl_info *info, struct drbd_adm_ctx *ctx)
{
	struct netlink_ext_ack *extack = info->extack;
	int result = ctx->result;
	const char *msg = NULL;
	int len = 0;

	if (!extack)
		return;

	/* what the command itself said, its first message only */
	if (ctx->msg_len) {
		len = strnlen(ctx->msg, ctx->msg_len);
		while (len && (ctx->msg[len - 1] == '\n' || ctx->msg[len - 1] == ' '))
			len--;
		if (len)
			msg = ctx->msg;
	}
	if (!msg) {
		msg = drbd2_is_ret_code(result) && drbd2_error_map[result].msg ?
			drbd2_error_map[result].msg : "DRBD command failed";
		len = strlen(msg);
	}
	NL_SET_ERR_MSG_FMT(extack, "%.*s",
			   min(len, NETLINK_MAX_FMTMSG_LEN - 1), msg);

	if (drbd2_is_ret_code(result) && drbd2_error_attr[result].nest) {
		struct nlattr *nest = info->attrs[drbd2_error_attr[result].nest];
		struct nlattr *attr = nest ?
			nla_find_nested(nest, drbd2_error_attr[result].attr) : NULL;

		if (attr)
			NL_SET_BAD_ATTR(extack, attr);
	}
}

/*
 * The drbd_state_rv of a completed state change as the state-result
 * attribute: the error values are the negated SS_* codes, the successful
 * outcomes follow above them in the order of the enum.
 */
static u32 drbd2_state_result(int result)
{
	if (result == NO_ERROR)
		return DRBD2_STATE_RESULT_SUCCESS;
	if (result >= SS_SUCCESS && result <= SS_CW_NO_NEED)
		return DRBD2_STATE_RESULT_SUCCESS + (result - SS_SUCCESS);
	if (result <= SS_UNKNOWN_ERROR && result > SS_AFTER_LAST_ERROR)
		return -result;
	return DRBD2_STATE_RESULT_UNKNOWN_ERROR;
}

/*
 * The info messages of the command, joined into the one string the
 * message attribute carries. They are NUL-separated in ctx->msg and this
 * is their last user, so the separators can be turned into newlines in
 * place; the final NUL stays and terminates the string.
 */
static int drbd2_put_message(struct sk_buff *skb, struct drbd_adm_ctx *ctx)
{
	unsigned int i;

	if (!ctx->msg_len)
		return 0;
	for (i = 0; i + 1 < ctx->msg_len; i++)
		if (ctx->msg[i] == '\0')
			ctx->msg[i] = '\n';
	return nla_put(skb, DRBD2_A_MESSAGE, ctx->msg_len, ctx->msg);
}

/*
 * Serialize the outcome of a completed command into the reply. The state
 * result always fits into a fresh message; the info text may not, and is
 * then dropped, exactly as the over-full legacy reply dropped it.
 */
static void drbd2_put_outcome(struct drbd_adm_ctx *ctx)
{
	struct drbd2_req *req = drbd2_req(ctx);

	if (req->payload_reply)
		return;
	if (nla_put_u32(req->reply_skb, DRBD2_A_STATE_RESULT,
			drbd2_state_result(ctx->result)))
		return;
	drbd2_put_message(req->reply_skb, ctx);
}

/*
 * The identity of an object, as the context nest of "attrtype". Every
 * pointer is optional; only the parts that are given are described.
 */
static int drbd2_put_context(struct sk_buff *skb, int attrtype,
			     struct drbd_resource *resource,
			     struct drbd_connection *connection,
			     struct drbd_device *device,
			     struct drbd_path *path)
{
	struct nlattr *nla = nla_nest_start(skb, attrtype);

	if (!nla)
		return -EMSGSIZE;
	if (resource && nla_put_string(skb, DRBD2_A_CONTEXT_RESOURCE_NAME, resource->name))
		goto fail;
	if (device &&
	    (nla_put_u32(skb, DRBD2_A_CONTEXT_VOLUME, device->vnr) ||
	     nla_put_u32(skb, DRBD2_A_CONTEXT_MINOR, device->minor)))
		goto fail;
	if (connection) {
		struct net_conf *nc;
		int err = 0;

		if (nla_put_u32(skb, DRBD2_A_CONTEXT_PEER_NODE_ID, connection->peer_node_id))
			goto fail;
		rcu_read_lock();
		nc = rcu_dereference(connection->transport.net_conf);
		if (nc)
			err = nla_put_string(skb, DRBD2_A_CONTEXT_CONNECTION_NAME, nc->name);
		rcu_read_unlock();
		if (err)
			goto fail;
	}
	if (path &&
	    (drbd2_put_address(skb, DRBD2_A_CONTEXT_MY_ADDRESS, &path->my_addr) ||
	     drbd2_put_address(skb, DRBD2_A_CONTEXT_PEER_ADDRESS, &path->peer_addr)))
		goto fail;
	nla_nest_end(skb, nla);
	return 0;

fail:
	nla_nest_cancel(skb, nla);
	return -EMSGSIZE;
}

/*
 * State and statistics of the five object types. The values of the drbd2
 * enums are those of the kernel-internal ones, so they go on the wire
 * unchanged.
 */

static int drbd2_put_resource_info(struct sk_buff *skb, int attrtype,
				   struct resource_info *info)
{
	struct nlattr *nla = nla_nest_start(skb, attrtype);

	if (!nla)
		return -EMSGSIZE;
	if (nla_put_u32(skb, DRBD2_A_RESOURCE_INFO_ROLE, info->res_role) ||
	    nla_put_u8(skb, DRBD2_A_RESOURCE_INFO_SUSP, info->res_susp) ||
	    nla_put_u8(skb, DRBD2_A_RESOURCE_INFO_SUSP_NOD, info->res_susp_nod) ||
	    nla_put_u8(skb, DRBD2_A_RESOURCE_INFO_SUSP_FEN, info->res_susp_fen) ||
	    nla_put_u8(skb, DRBD2_A_RESOURCE_INFO_SUSP_QUORUM, info->res_susp_quorum) ||
	    nla_put_u8(skb, DRBD2_A_RESOURCE_INFO_FAIL_IO, info->res_fail_io))
		goto fail;
	nla_nest_end(skb, nla);
	return 0;

fail:
	nla_nest_cancel(skb, nla);
	return -EMSGSIZE;
}

static int drbd2_put_resource_statistics(struct sk_buff *skb, int attrtype,
					 struct resource_statistics *s)
{
	struct nlattr *nla = nla_nest_start(skb, attrtype);

	if (!nla)
		return -EMSGSIZE;
	if (nla_put_u32(skb, DRBD2_A_RESOURCE_STATISTICS_WRITE_ORDERING,
			s->res_stat_write_ordering))
		goto fail;
	nla_nest_end(skb, nla);
	return 0;

fail:
	nla_nest_cancel(skb, nla);
	return -EMSGSIZE;
}

static int drbd2_put_device_info(struct sk_buff *skb, int attrtype,
				 struct device_info *info)
{
	struct nlattr *nla = nla_nest_start(skb, attrtype);

	if (!nla)
		return -EMSGSIZE;
	if (nla_put_u32(skb, DRBD2_A_DEVICE_INFO_DISK_STATE, info->dev_disk_state) ||
	    nla_put_u8(skb, DRBD2_A_DEVICE_INFO_IS_INTENTIONAL_DISKLESS,
		       info->is_intentional_diskless) ||
	    nla_put_u8(skb, DRBD2_A_DEVICE_INFO_HAS_QUORUM, info->dev_has_quorum) ||
	    nla_put_u8(skb, DRBD2_A_DEVICE_INFO_IS_OPEN, info->dev_is_open) ||
	    drbd2_put_str(skb, DRBD2_A_DEVICE_INFO_BACKING_DEV_PATH,
			  info->backing_dev_path, info->backing_dev_path_len,
			  sizeof(info->backing_dev_path)))
		goto fail;
	nla_nest_end(skb, nla);
	return 0;

fail:
	nla_nest_cancel(skb, nla);
	return -EMSGSIZE;
}

static int drbd2_put_device_statistics(struct sk_buff *skb, int attrtype,
				       struct device_statistics *s)
{
	struct nlattr *nla = nla_nest_start(skb, attrtype);

	if (!nla)
		return -EMSGSIZE;
	if (drbd2_put_u64(skb, DRBD2_A_DEVICE_STATISTICS_SIZE, s->dev_size) ||
	    drbd2_put_u64(skb, DRBD2_A_DEVICE_STATISTICS_READ, s->dev_read) ||
	    drbd2_put_u64(skb, DRBD2_A_DEVICE_STATISTICS_WRITE, s->dev_write) ||
	    drbd2_put_u64(skb, DRBD2_A_DEVICE_STATISTICS_AL_WRITES, s->dev_al_writes) ||
	    drbd2_put_u64(skb, DRBD2_A_DEVICE_STATISTICS_BM_WRITES, s->dev_bm_writes) ||
	    nla_put_u32(skb, DRBD2_A_DEVICE_STATISTICS_UPPER_PENDING, s->dev_upper_pending) ||
	    nla_put_u32(skb, DRBD2_A_DEVICE_STATISTICS_LOWER_PENDING, s->dev_lower_pending) ||
	    nla_put_u8(skb, DRBD2_A_DEVICE_STATISTICS_UPPER_BLOCKED, s->dev_upper_blocked) ||
	    nla_put_u8(skb, DRBD2_A_DEVICE_STATISTICS_LOWER_BLOCKED, s->dev_lower_blocked) ||
	    nla_put_u8(skb, DRBD2_A_DEVICE_STATISTICS_AL_SUSPENDED, s->dev_al_suspended) ||
	    drbd2_put_u64(skb, DRBD2_A_DEVICE_STATISTICS_EXPOSED_DATA_UUID,
			  s->dev_exposed_data_uuid) ||
	    drbd2_put_u64(skb, DRBD2_A_DEVICE_STATISTICS_CURRENT_UUID, s->dev_current_uuid) ||
	    nla_put_u32(skb, DRBD2_A_DEVICE_STATISTICS_DISK_FLAGS, s->dev_disk_flags) ||
	    nla_put(skb, DRBD2_A_DEVICE_STATISTICS_HISTORY_UUIDS,
		    min_t(u32, HISTORY_UUIDS_SIZE, s->history_uuids_len), s->history_uuids))
		goto fail;
	nla_nest_end(skb, nla);
	return 0;

fail:
	nla_nest_cancel(skb, nla);
	return -EMSGSIZE;
}

static int drbd2_put_connection_info(struct sk_buff *skb, int attrtype,
				     struct connection_info *info)
{
	struct nlattr *nla = nla_nest_start(skb, attrtype);

	if (!nla)
		return -EMSGSIZE;
	if (nla_put_u32(skb, DRBD2_A_CONNECTION_INFO_CONNECTION_STATE,
			info->conn_connection_state) ||
	    nla_put_u32(skb, DRBD2_A_CONNECTION_INFO_ROLE, info->conn_role))
		goto fail;
	nla_nest_end(skb, nla);
	return 0;

fail:
	nla_nest_cancel(skb, nla);
	return -EMSGSIZE;
}

static int drbd2_put_connection_statistics(struct sk_buff *skb, int attrtype,
					   struct connection_statistics *s)
{
	struct nlattr *nla = nla_nest_start(skb, attrtype);

	if (!nla)
		return -EMSGSIZE;
	if (nla_put_u8(skb, DRBD2_A_CONNECTION_STATISTICS_CONGESTED, s->conn_congested) ||
	    drbd2_put_u64(skb, DRBD2_A_CONNECTION_STATISTICS_AP_IN_FLIGHT, s->ap_in_flight) ||
	    drbd2_put_u64(skb, DRBD2_A_CONNECTION_STATISTICS_RS_IN_FLIGHT, s->rs_in_flight))
		goto fail;
	nla_nest_end(skb, nla);
	return 0;

fail:
	nla_nest_cancel(skb, nla);
	return -EMSGSIZE;
}

static int drbd2_put_peer_device_info(struct sk_buff *skb, int attrtype,
				      struct peer_device_info *info)
{
	struct nlattr *nla = nla_nest_start(skb, attrtype);

	if (!nla)
		return -EMSGSIZE;
	if (nla_put_u32(skb, DRBD2_A_PEER_DEVICE_INFO_REPL_STATE, info->peer_repl_state) ||
	    nla_put_u32(skb, DRBD2_A_PEER_DEVICE_INFO_DISK_STATE, info->peer_disk_state) ||
	    nla_put_u8(skb, DRBD2_A_PEER_DEVICE_INFO_RESYNC_SUSP_USER,
		       !!info->peer_resync_susp_user) ||
	    nla_put_u8(skb, DRBD2_A_PEER_DEVICE_INFO_RESYNC_SUSP_PEER,
		       !!info->peer_resync_susp_peer) ||
	    nla_put_u8(skb, DRBD2_A_PEER_DEVICE_INFO_RESYNC_SUSP_DEPENDENCY,
		       !!info->peer_resync_susp_dependency) ||
	    nla_put_u8(skb, DRBD2_A_PEER_DEVICE_INFO_IS_INTENTIONAL_DISKLESS,
		       info->peer_is_intentional_diskless) ||
	    nla_put_u8(skb, DRBD2_A_PEER_DEVICE_INFO_RESYNC_SUSP_MAX_PARALLEL,
		       !!info->peer_resync_susp_max_parallel))
		goto fail;
	nla_nest_end(skb, nla);
	return 0;

fail:
	nla_nest_cancel(skb, nla);
	return -EMSGSIZE;
}

static int drbd2_put_peer_device_statistics(struct sk_buff *skb, int attrtype,
					    struct peer_device_statistics *s)
{
	struct nlattr *nla = nla_nest_start(skb, attrtype);

	if (!nla)
		return -EMSGSIZE;
	if (drbd2_put_u64(skb, DRBD2_A_PEER_DEVICE_STATISTICS_RECEIVED, s->peer_dev_received) ||
	    drbd2_put_u64(skb, DRBD2_A_PEER_DEVICE_STATISTICS_SENT, s->peer_dev_sent) ||
	    nla_put_u32(skb, DRBD2_A_PEER_DEVICE_STATISTICS_PENDING, s->peer_dev_pending) ||
	    nla_put_u32(skb, DRBD2_A_PEER_DEVICE_STATISTICS_UNACKED, s->peer_dev_unacked) ||
	    drbd2_put_u64(skb, DRBD2_A_PEER_DEVICE_STATISTICS_OUT_OF_SYNC,
			  s->peer_dev_out_of_sync) ||
	    drbd2_put_u64(skb, DRBD2_A_PEER_DEVICE_STATISTICS_RESYNC_FAILED,
			  s->peer_dev_resync_failed) ||
	    drbd2_put_u64(skb, DRBD2_A_PEER_DEVICE_STATISTICS_BITMAP_UUID,
			  s->peer_dev_bitmap_uuid) ||
	    nla_put_u32(skb, DRBD2_A_PEER_DEVICE_STATISTICS_FLAGS, s->peer_dev_flags) ||
	    drbd2_put_u64(skb, DRBD2_A_PEER_DEVICE_STATISTICS_RS_TOTAL, s->peer_dev_rs_total) ||
	    drbd2_put_u64(skb, DRBD2_A_PEER_DEVICE_STATISTICS_OV_START_SECTOR,
			  s->peer_dev_ov_start_sector) ||
	    drbd2_put_u64(skb, DRBD2_A_PEER_DEVICE_STATISTICS_OV_STOP_SECTOR,
			  s->peer_dev_ov_stop_sector) ||
	    drbd2_put_u64(skb, DRBD2_A_PEER_DEVICE_STATISTICS_OV_POSITION,
			  s->peer_dev_ov_position) ||
	    drbd2_put_u64(skb, DRBD2_A_PEER_DEVICE_STATISTICS_OV_LEFT, s->peer_dev_ov_left) ||
	    drbd2_put_u64(skb, DRBD2_A_PEER_DEVICE_STATISTICS_OV_SKIPPED,
			  s->peer_dev_ov_skipped) ||
	    drbd2_put_u64(skb, DRBD2_A_PEER_DEVICE_STATISTICS_RS_SAME_CSUM,
			  s->peer_dev_rs_same_csum) ||
	    drbd2_put_u64(skb, DRBD2_A_PEER_DEVICE_STATISTICS_RS_DT_START_MS,
			  s->peer_dev_rs_dt_start_ms) ||
	    drbd2_put_u64(skb, DRBD2_A_PEER_DEVICE_STATISTICS_RS_PAUSED_MS,
			  s->peer_dev_rs_paused_ms) ||
	    drbd2_put_u64(skb, DRBD2_A_PEER_DEVICE_STATISTICS_RS_DT0_MS,
			  s->peer_dev_rs_dt0_ms) ||
	    drbd2_put_u64(skb, DRBD2_A_PEER_DEVICE_STATISTICS_RS_DB0_SECTORS,
			  s->peer_dev_rs_db0_sectors) ||
	    drbd2_put_u64(skb, DRBD2_A_PEER_DEVICE_STATISTICS_RS_DT1_MS,
			  s->peer_dev_rs_dt1_ms) ||
	    drbd2_put_u64(skb, DRBD2_A_PEER_DEVICE_STATISTICS_RS_DB1_SECTORS,
			  s->peer_dev_rs_db1_sectors) ||
	    nla_put_u32(skb, DRBD2_A_PEER_DEVICE_STATISTICS_RS_C_SYNC_RATE,
			s->peer_dev_rs_c_sync_rate) ||
	    drbd2_put_u64(skb, DRBD2_A_PEER_DEVICE_STATISTICS_UUID_FLAGS,
			  s->peer_dev_uuid_flags))
		goto fail;
	nla_nest_end(skb, nla);
	return 0;

fail:
	nla_nest_cancel(skb, nla);
	return -EMSGSIZE;
}

static int drbd2_put_path_info(struct sk_buff *skb, int attrtype,
			       struct drbd_path_info *info)
{
	struct nlattr *nla = nla_nest_start(skb, attrtype);

	if (!nla)
		return -EMSGSIZE;
	if (nla_put_u8(skb, DRBD2_A_PATH_INFO_ESTABLISHED, info->path_established))
		goto fail;
	nla_nest_end(skb, nla);
	return 0;

fail:
	nla_nest_cancel(skb, nla);
	return -EMSGSIZE;
}

/*
 * The configuration of a live object, for the dumps. The notifications
 * describe state changes and carry no configuration, so they pass NULL.
 */

static int drbd2_put_res_opts(struct sk_buff *skb, int attrtype, struct res_opts *c)
{
	struct nlattr *nla = nla_nest_start(skb, attrtype);

	if (!nla)
		return -EMSGSIZE;
	if (drbd2_put_str(skb, DRBD2_A_RESOURCE_OPTS_CPU_MASK, c->cpu_mask,
			  c->cpu_mask_len, sizeof(c->cpu_mask)) ||
	    nla_put_u32(skb, DRBD2_A_RESOURCE_OPTS_ON_NO_DATA_ACCESSIBLE, c->on_no_data) ||
	    nla_put_u8(skb, DRBD2_A_RESOURCE_OPTS_AUTO_PROMOTE, c->auto_promote) ||
	    nla_put_u32(skb, DRBD2_A_RESOURCE_OPTS_NODE_ID, c->node_id) ||
	    nla_put_u32(skb, DRBD2_A_RESOURCE_OPTS_PEER_ACK_WINDOW, c->peer_ack_window) ||
	    nla_put_u32(skb, DRBD2_A_RESOURCE_OPTS_TWOPC_TIMEOUT, c->twopc_timeout) ||
	    nla_put_u32(skb, DRBD2_A_RESOURCE_OPTS_TWOPC_RETRY_TIMEOUT,
			c->twopc_retry_timeout) ||
	    nla_put_u32(skb, DRBD2_A_RESOURCE_OPTS_PEER_ACK_DELAY, c->peer_ack_delay) ||
	    nla_put_u32(skb, DRBD2_A_RESOURCE_OPTS_AUTO_PROMOTE_TIMEOUT,
			c->auto_promote_timeout) ||
	    nla_put_u32(skb, DRBD2_A_RESOURCE_OPTS_MAX_IO_DEPTH, c->nr_requests) ||
	    nla_put_s32(skb, DRBD2_A_RESOURCE_OPTS_QUORUM, c->quorum) ||
	    nla_put_u32(skb, DRBD2_A_RESOURCE_OPTS_ON_NO_QUORUM, c->on_no_quorum) ||
	    nla_put_s32(skb, DRBD2_A_RESOURCE_OPTS_QUORUM_MIN_REDUNDANCY,
			c->quorum_min_redundancy) ||
	    nla_put_u32(skb, DRBD2_A_RESOURCE_OPTS_ON_SUSPENDED_PRIMARY_OUTDATED,
			c->on_susp_primary_outdated) ||
	    nla_put_u8(skb, DRBD2_A_RESOURCE_OPTS_DRBD8_COMPAT_MODE, c->drbd8_compat_mode) ||
	    nla_put_u8(skb, DRBD2_A_RESOURCE_OPTS_EXPLICIT_DRBD8_COMPAT,
		       c->explicit_drbd8_compat))
		goto fail;
	nla_nest_end(skb, nla);
	return 0;

fail:
	nla_nest_cancel(skb, nla);
	return -EMSGSIZE;
}

static int drbd2_put_disk_conf(struct sk_buff *skb, int attrtype, struct disk_conf *c)
{
	struct nlattr *nla = nla_nest_start(skb, attrtype);

	if (!nla)
		return -EMSGSIZE;
	if (drbd2_put_str(skb, DRBD2_A_DISK_CONF_BACKING_DEV, c->backing_dev,
			  c->backing_dev_len, sizeof(c->backing_dev)) ||
	    drbd2_put_str(skb, DRBD2_A_DISK_CONF_META_DEV, c->meta_dev,
			  c->meta_dev_len, sizeof(c->meta_dev)) ||
	    nla_put_s32(skb, DRBD2_A_DISK_CONF_META_DEV_IDX, c->meta_dev_idx) ||
	    drbd2_put_u64(skb, DRBD2_A_DISK_CONF_SIZE, c->disk_size) ||
	    nla_put_u32(skb, DRBD2_A_DISK_CONF_ON_IO_ERROR, c->on_io_error) ||
	    nla_put_s32(skb, DRBD2_A_DISK_CONF_RESYNC_AFTER, c->resync_after) ||
	    nla_put_u32(skb, DRBD2_A_DISK_CONF_AL_EXTENTS, c->al_extents) ||
	    nla_put_u8(skb, DRBD2_A_DISK_CONF_DISK_BARRIER, c->disk_barrier) ||
	    nla_put_u8(skb, DRBD2_A_DISK_CONF_DISK_FLUSHES, c->disk_flushes) ||
	    nla_put_u8(skb, DRBD2_A_DISK_CONF_DISK_DRAIN, c->disk_drain) ||
	    nla_put_u8(skb, DRBD2_A_DISK_CONF_MD_FLUSHES, c->md_flushes) ||
	    nla_put_u32(skb, DRBD2_A_DISK_CONF_DISK_TIMEOUT, c->disk_timeout) ||
	    nla_put_u32(skb, DRBD2_A_DISK_CONF_READ_BALANCING, c->read_balancing) ||
	    nla_put_u32(skb, DRBD2_A_DISK_CONF_UNPLUG_WATERMARK, c->unplug_watermark) ||
	    nla_put_u32(skb, DRBD2_A_DISK_CONF_RS_DISCARD_GRANULARITY,
			c->rs_discard_granularity) ||
	    nla_put_u8(skb, DRBD2_A_DISK_CONF_AL_UPDATES, c->al_updates) ||
	    nla_put_u8(skb, DRBD2_A_DISK_CONF_DISCARD_ZEROES_IF_ALIGNED,
		       c->discard_zeroes_if_aligned) ||
	    nla_put_u8(skb, DRBD2_A_DISK_CONF_DISABLE_WRITE_SAME, c->disable_write_same) ||
	    nla_put_u8(skb, DRBD2_A_DISK_CONF_BITMAP, c->d_bitmap))
		goto fail;
	nla_nest_end(skb, nla);
	return 0;

fail:
	nla_nest_cancel(skb, nla);
	return -EMSGSIZE;
}

/*
 * The caller decides what the reader may see: the dump hands us a copy
 * with the shared secret cleared unless the reader has CAP_SYS_ADMIN.
 */
static int drbd2_put_net_conf(struct sk_buff *skb, int attrtype, struct net_conf *c)
{
	struct nlattr *nla = nla_nest_start(skb, attrtype);

	if (!nla)
		return -EMSGSIZE;
	if (drbd2_put_str(skb, DRBD2_A_NET_CONF_SHARED_SECRET, c->shared_secret,
			  c->shared_secret_len, sizeof(c->shared_secret)) ||
	    drbd2_put_str(skb, DRBD2_A_NET_CONF_CRAM_HMAC_ALG, c->cram_hmac_alg,
			  c->cram_hmac_alg_len, sizeof(c->cram_hmac_alg)) ||
	    drbd2_put_str(skb, DRBD2_A_NET_CONF_INTEGRITY_ALG, c->integrity_alg,
			  c->integrity_alg_len, sizeof(c->integrity_alg)) ||
	    drbd2_put_str(skb, DRBD2_A_NET_CONF_VERIFY_ALG, c->verify_alg,
			  c->verify_alg_len, sizeof(c->verify_alg)) ||
	    drbd2_put_str(skb, DRBD2_A_NET_CONF_CSUMS_ALG, c->csums_alg,
			  c->csums_alg_len, sizeof(c->csums_alg)) ||
	    nla_put_u32(skb, DRBD2_A_NET_CONF_PROTOCOL, c->wire_protocol) ||
	    nla_put_u32(skb, DRBD2_A_NET_CONF_CONNECT_INT, c->connect_int) ||
	    nla_put_u32(skb, DRBD2_A_NET_CONF_TIMEOUT, c->timeout) ||
	    nla_put_u32(skb, DRBD2_A_NET_CONF_PING_INT, c->ping_int) ||
	    nla_put_u32(skb, DRBD2_A_NET_CONF_PING_TIMEO, c->ping_timeo) ||
	    nla_put_u32(skb, DRBD2_A_NET_CONF_SNDBUF_SIZE, c->sndbuf_size) ||
	    nla_put_u32(skb, DRBD2_A_NET_CONF_RCVBUF_SIZE, c->rcvbuf_size) ||
	    nla_put_u32(skb, DRBD2_A_NET_CONF_KO_COUNT, c->ko_count) ||
	    nla_put_u32(skb, DRBD2_A_NET_CONF_MAX_EPOCH_SIZE, c->max_epoch_size) ||
	    nla_put_u32(skb, DRBD2_A_NET_CONF_AFTER_SB_0PRI, c->after_sb_0p) ||
	    nla_put_u32(skb, DRBD2_A_NET_CONF_AFTER_SB_1PRI, c->after_sb_1p) ||
	    nla_put_u32(skb, DRBD2_A_NET_CONF_AFTER_SB_2PRI, c->after_sb_2p) ||
	    nla_put_u32(skb, DRBD2_A_NET_CONF_RR_CONFLICT, c->rr_conflict) ||
	    nla_put_u32(skb, DRBD2_A_NET_CONF_ON_CONGESTION, c->on_congestion) ||
	    nla_put_u32(skb, DRBD2_A_NET_CONF_CONG_FILL, c->cong_fill) ||
	    nla_put_u32(skb, DRBD2_A_NET_CONF_CONG_EXTENTS, c->cong_extents) ||
	    nla_put_u8(skb, DRBD2_A_NET_CONF_TWO_PRIMARIES, c->two_primaries) ||
	    nla_put_u8(skb, DRBD2_A_NET_CONF_TCP_CORK, c->tcp_cork) ||
	    nla_put_u8(skb, DRBD2_A_NET_CONF_ALWAYS_ASBP, c->always_asbp) ||
	    nla_put_u8(skb, DRBD2_A_NET_CONF_USE_RLE, c->use_rle) ||
	    nla_put_u32(skb, DRBD2_A_NET_CONF_FENCING, c->fencing_policy) ||
	    drbd2_put_str(skb, DRBD2_A_NET_CONF_CONNECTION_NAME, c->name,
			  c->name_len, sizeof(c->name)) ||
	    nla_put_u8(skb, DRBD2_A_NET_CONF_CSUMS_AFTER_CRASH_ONLY,
		       c->csums_after_crash_only) ||
	    nla_put_u32(skb, DRBD2_A_NET_CONF_SOCK_CHECK_TIMEO, c->sock_check_timeo) ||
	    drbd2_put_str(skb, DRBD2_A_NET_CONF_TRANSPORT_NAME, c->transport_name,
			  c->transport_name_len, sizeof(c->transport_name)) ||
	    nla_put_u32(skb, DRBD2_A_NET_CONF_MAX_BUFFERS, c->max_buffers) ||
	    nla_put_u8(skb, DRBD2_A_NET_CONF_ALLOW_REMOTE_READ, c->allow_remote_read) ||
	    nla_put_u8(skb, DRBD2_A_NET_CONF_TLS, c->tls) ||
	    nla_put_s32(skb, DRBD2_A_NET_CONF_TLS_PRIVKEY, c->tls_privkey) ||
	    nla_put_s32(skb, DRBD2_A_NET_CONF_TLS_CERTIFICATE, c->tls_certificate) ||
	    nla_put_s32(skb, DRBD2_A_NET_CONF_TLS_KEYRING, c->tls_keyring) ||
	    nla_put_u8(skb, DRBD2_A_NET_CONF_LOAD_BALANCE_PATHS, c->load_balance_paths) ||
	    nla_put_u32(skb, DRBD2_A_NET_CONF_RDMA_CTRL_RCVBUF_SIZE,
			c->rdma_ctrl_rcvbuf_size) ||
	    nla_put_u32(skb, DRBD2_A_NET_CONF_RDMA_CTRL_SNDBUF_SIZE,
			c->rdma_ctrl_sndbuf_size))
		goto fail;
	nla_nest_end(skb, nla);
	return 0;

fail:
	nla_nest_cancel(skb, nla);
	return -EMSGSIZE;
}

static int drbd2_put_device_conf(struct sk_buff *skb, int attrtype, struct device_conf *c)
{
	struct nlattr *nla = nla_nest_start(skb, attrtype);

	if (!nla)
		return -EMSGSIZE;
	if (nla_put_u32(skb, DRBD2_A_DEVICE_CONF_MAX_BIO_SIZE, c->max_bio_size) ||
	    nla_put_u8(skb, DRBD2_A_DEVICE_CONF_INTENTIONAL_DISKLESS,
		       c->intentional_diskless) ||
	    nla_put_u32(skb, DRBD2_A_DEVICE_CONF_BLOCK_SIZE, c->block_size) ||
	    nla_put_u32(skb, DRBD2_A_DEVICE_CONF_DISCARD_GRANULARITY,
			c->discard_granularity))
		goto fail;
	nla_nest_end(skb, nla);
	return 0;

fail:
	nla_nest_cancel(skb, nla);
	return -EMSGSIZE;
}

static int drbd2_put_peer_device_conf(struct sk_buff *skb, int attrtype,
				      struct peer_device_conf *c)
{
	struct nlattr *nla = nla_nest_start(skb, attrtype);

	if (!nla)
		return -EMSGSIZE;
	if (nla_put_u32(skb, DRBD2_A_PEER_DEVICE_CONF_RESYNC_RATE, c->resync_rate) ||
	    nla_put_u32(skb, DRBD2_A_PEER_DEVICE_CONF_C_PLAN_AHEAD, c->c_plan_ahead) ||
	    nla_put_u32(skb, DRBD2_A_PEER_DEVICE_CONF_C_DELAY_TARGET, c->c_delay_target) ||
	    nla_put_u32(skb, DRBD2_A_PEER_DEVICE_CONF_C_FILL_TARGET, c->c_fill_target) ||
	    nla_put_u32(skb, DRBD2_A_PEER_DEVICE_CONF_C_MAX_RATE, c->c_max_rate) ||
	    nla_put_u32(skb, DRBD2_A_PEER_DEVICE_CONF_C_MIN_RATE, c->c_min_rate) ||
	    nla_put_u8(skb, DRBD2_A_PEER_DEVICE_CONF_BITMAP, c->bitmap) ||
	    nla_put_u8(skb, DRBD2_A_PEER_DEVICE_CONF_RESYNC_WITHOUT_REPLICATION,
		       c->resync_without_replication) ||
	    nla_put_u8(skb, DRBD2_A_PEER_DEVICE_CONF_PEER_TIEBREAKER, c->peer_tiebreaker))
		goto fail;
	nla_nest_end(skb, nla);
	return 0;

fail:
	nla_nest_cancel(skb, nla);
	return -EMSGSIZE;
}

/*
 * The paths of a connection, one attribute each, carried inside the
 * connection nest as the legacy family carried them inside its
 * connection message. Only the addresses identify a path here; the
 * enclosing nest already names the resource and the peer.
 */
static int drbd2_put_connection_paths(struct sk_buff *skb,
				      struct drbd_connection *connection)
{
	struct drbd_path *path;
	int err = 0;

	rcu_read_lock();
	list_for_each_entry_rcu(path, &connection->transport.paths, list) {
		struct drbd_path_info info = {
			.path_established = test_bit(TR_ESTABLISHED, &path->flags),
		};
		struct nlattr *nla = nla_nest_start(skb, DRBD2_A_CONNECTION_PATH);

		if (!nla) {
			err = -EMSGSIZE;
			break;
		}
		if (drbd2_put_context(skb, DRBD2_A_PATH_CONTEXT, NULL, NULL, NULL, path) ||
		    drbd2_put_path_info(skb, DRBD2_A_PATH_INFO, &info)) {
			nla_nest_cancel(skb, nla);
			err = -EMSGSIZE;
			break;
		}
		nla_nest_end(skb, nla);
	}
	rcu_read_unlock();
	return err;
}

/*
 * The object nests shared by the dumps and the state change messages:
 * one nest per object type, holding its context, state and statistics.
 */

static int drbd2_put_resource(struct sk_buff *skb, int attrtype,
			      struct drbd_resource *resource,
			      struct res_opts *res_opts,
			      struct resource_info *info,
			      struct resource_statistics *statistics,
			      struct rename_resource_info *rename_info)
{
	struct nlattr *nla = nla_nest_start(skb, attrtype);

	if (!nla)
		return -EMSGSIZE;
	if (drbd2_put_context(skb, DRBD2_A_RESOURCE_CONTEXT, resource, NULL, NULL, NULL))
		goto fail;
	if (info && drbd2_put_resource_info(skb, DRBD2_A_RESOURCE_INFO, info))
		goto fail;
	if (statistics &&
	    drbd2_put_resource_statistics(skb, DRBD2_A_RESOURCE_STATISTICS, statistics))
		goto fail;
	if (rename_info &&
	    drbd2_put_str(skb, DRBD2_A_RESOURCE_NEW_NAME, rename_info->res_new_name,
			  rename_info->res_new_name_len, sizeof(rename_info->res_new_name)))
		goto fail;
	if (res_opts && drbd2_put_res_opts(skb, DRBD2_A_RESOURCE_RESOURCE_OPTS, res_opts))
		goto fail;
	nla_nest_end(skb, nla);
	return 0;

fail:
	nla_nest_cancel(skb, nla);
	return -EMSGSIZE;
}

static int drbd2_put_device(struct sk_buff *skb, int attrtype,
			    struct drbd_device *device,
			    struct disk_conf *disk_conf,
			    struct device_conf *device_conf,
			    struct device_info *info,
			    struct device_statistics *statistics)
{
	struct nlattr *nla = nla_nest_start(skb, attrtype);

	if (!nla)
		return -EMSGSIZE;
	if (drbd2_put_context(skb, DRBD2_A_DEVICE_CONTEXT, device->resource, NULL, device, NULL))
		goto fail;
	if (info && drbd2_put_device_info(skb, DRBD2_A_DEVICE_INFO, info))
		goto fail;
	if (statistics &&
	    drbd2_put_device_statistics(skb, DRBD2_A_DEVICE_STATISTICS, statistics))
		goto fail;
	if (disk_conf && drbd2_put_disk_conf(skb, DRBD2_A_DEVICE_DISK_CONF, disk_conf))
		goto fail;
	if (device_conf &&
	    drbd2_put_device_conf(skb, DRBD2_A_DEVICE_DEVICE_CONF, device_conf))
		goto fail;
	nla_nest_end(skb, nla);
	return 0;

fail:
	nla_nest_cancel(skb, nla);
	return -EMSGSIZE;
}

static int drbd2_put_connection(struct sk_buff *skb, int attrtype,
				struct drbd_resource *resource,
				struct drbd_connection *connection,
				struct net_conf *net_conf,
				struct connection_info *info,
				struct connection_statistics *statistics)
{
	struct nlattr *nla = nla_nest_start(skb, attrtype);

	if (!nla)
		return -EMSGSIZE;
	if (drbd2_put_context(skb, DRBD2_A_CONNECTION_CONTEXT, resource, connection, NULL, NULL))
		goto fail;
	if (info && drbd2_put_connection_info(skb, DRBD2_A_CONNECTION_INFO, info))
		goto fail;
	if (statistics &&
	    drbd2_put_connection_statistics(skb, DRBD2_A_CONNECTION_STATISTICS, statistics))
		goto fail;
	if (net_conf && drbd2_put_net_conf(skb, DRBD2_A_CONNECTION_NET_CONF, net_conf))
		goto fail;
	if (drbd2_put_connection_paths(skb, connection))
		goto fail;
	nla_nest_end(skb, nla);
	return 0;

fail:
	nla_nest_cancel(skb, nla);
	return -EMSGSIZE;
}

static int drbd2_put_peer_device(struct sk_buff *skb, int attrtype,
				 struct drbd_peer_device *peer_device,
				 struct peer_device_conf *conf,
				 struct peer_device_info *info,
				 struct peer_device_statistics *statistics)
{
	struct drbd_device *device = peer_device->device;
	struct nlattr *nla = nla_nest_start(skb, attrtype);

	if (!nla)
		return -EMSGSIZE;
	if (drbd2_put_context(skb, DRBD2_A_PEER_DEVICE_CONTEXT, device->resource,
			      peer_device->connection, device, NULL))
		goto fail;
	if (info && drbd2_put_peer_device_info(skb, DRBD2_A_PEER_DEVICE_INFO, info))
		goto fail;
	if (statistics &&
	    drbd2_put_peer_device_statistics(skb, DRBD2_A_PEER_DEVICE_STATISTICS, statistics))
		goto fail;
	if (conf &&
	    drbd2_put_peer_device_conf(skb, DRBD2_A_PEER_DEVICE_PEER_DEVICE_CONF, conf))
		goto fail;
	nla_nest_end(skb, nla);
	return 0;

fail:
	nla_nest_cancel(skb, nla);
	return -EMSGSIZE;
}

static int drbd2_put_path(struct sk_buff *skb, int attrtype,
			  struct drbd_resource *resource,
			  struct drbd_connection *connection,
			  struct drbd_path *path,
			  struct drbd_path_info *info)
{
	struct nlattr *nla = nla_nest_start(skb, attrtype);

	if (!nla)
		return -EMSGSIZE;
	if (drbd2_put_context(skb, DRBD2_A_PATH_CONTEXT, resource, connection, NULL, path))
		goto fail;
	if (info && drbd2_put_path_info(skb, DRBD2_A_PATH_INFO, info))
		goto fail;
	nla_nest_end(skb, nla);
	return 0;

fail:
	nla_nest_cancel(skb, nla);
	return -EMSGSIZE;
}

/*
 * pre_doit / post_doit.
 */

/* Which objects a command needs resolved, indexed by DRBD2_CMD_*. */
static const unsigned int drbd2_cmd_flags[] = {
	[DRBD2_CMD_RESOURCE_NEW]		= 0,
	[DRBD2_CMD_RESOURCE_DEL]		= DRBD_ADM_NEED_RESOURCE,
	[DRBD2_CMD_RESOURCE_SET]		= DRBD_ADM_NEED_RESOURCE,
	[DRBD2_CMD_RESOURCE_RENAME]		= DRBD_ADM_NEED_RESOURCE,
	[DRBD2_CMD_RESOURCE_DOWN]		= DRBD_ADM_NEED_RESOURCE,
	[DRBD2_CMD_RESOURCE_PRIMARY]		= DRBD_ADM_NEED_RESOURCE,
	[DRBD2_CMD_RESOURCE_SECONDARY]		= DRBD_ADM_NEED_RESOURCE,
	/* both act on all devices of the resource, but reach it via a minor */
	[DRBD2_CMD_RESOURCE_SUSPEND_IO]		= DRBD_ADM_NEED_MINOR,
	[DRBD2_CMD_RESOURCE_RESUME_IO]		= DRBD_ADM_NEED_MINOR,
	[DRBD2_CMD_DEVICE_NEW]			= DRBD_ADM_NEED_RESOURCE,
	[DRBD2_CMD_DEVICE_DEL]			= DRBD_ADM_NEED_MINOR,
	[DRBD2_CMD_DEVICE_ATTACH]		= DRBD_ADM_NEED_MINOR,
	[DRBD2_CMD_DEVICE_DETACH]		= DRBD_ADM_NEED_MINOR,
	[DRBD2_CMD_DISK_SET]			= DRBD_ADM_NEED_MINOR,
	[DRBD2_CMD_DEVICE_RESIZE]		= DRBD_ADM_NEED_MINOR,
	[DRBD2_CMD_DEVICE_OUTDATE]		= DRBD_ADM_NEED_MINOR,
	[DRBD2_CMD_DEVICE_INVALIDATE]		= DRBD_ADM_NEED_MINOR,
	[DRBD2_CMD_DEVICE_NEW_CURRENT_UUID]	= DRBD_ADM_NEED_MINOR,
	[DRBD2_CMD_CONNECTION_NEW]		= DRBD_ADM_NEED_PEER_NODE,
	[DRBD2_CMD_CONNECTION_DEL]		= DRBD_ADM_NEED_CONNECTION,
	[DRBD2_CMD_CONNECTION_CONNECT]		= DRBD_ADM_NEED_CONNECTION,
	[DRBD2_CMD_CONNECTION_DISCONNECT]	= DRBD_ADM_NEED_CONNECTION,
	[DRBD2_CMD_CONNECTION_SET]		= DRBD_ADM_NEED_CONNECTION,
	/* the peer to forget must not have a connection any more */
	[DRBD2_CMD_CONNECTION_FORGET]		= DRBD_ADM_NEED_RESOURCE,
	[DRBD2_CMD_PATH_NEW]			= DRBD_ADM_NEED_CONNECTION,
	[DRBD2_CMD_PATH_DEL]			= DRBD_ADM_NEED_CONNECTION,
	[DRBD2_CMD_PEER_DEVICE_SET]		= DRBD_ADM_NEED_PEER_DEVICE,
	[DRBD2_CMD_PEER_DEVICE_INVALIDATE]	= DRBD_ADM_NEED_PEER_DEVICE,
	[DRBD2_CMD_PEER_DEVICE_PAUSE_SYNC]	= DRBD_ADM_NEED_PEER_DEVICE,
	[DRBD2_CMD_PEER_DEVICE_RESUME_SYNC]	= DRBD_ADM_NEED_PEER_DEVICE,
	[DRBD2_CMD_PEER_DEVICE_START_OV]	= DRBD_ADM_NEED_PEER_DEVICE,
	[DRBD2_CMD_TIMEOUT_TYPE_GET]		= DRBD_ADM_NEED_PEER_DEVICE,
};

/* Fill in the identity of the object the request refers to. */
static int drbd2_parse_context(struct drbd_adm_ctx *ctx, struct genl_info *info)
{
	struct nlattr *tb[DRBD2_A_CONTEXT_PEER_ADDRESS + 1];
	int err;

	ctx->minor = MINORMASK + 1;	/* no such minor */
	ctx->volume = VOLUME_UNSPECIFIED;
	ctx->peer_node_id = PEER_NODE_ID_UNSPECIFIED;

	if (!info->attrs[DRBD2_A_CONTEXT])
		return 0;

	err = nla_parse_nested(tb, DRBD2_A_CONTEXT_PEER_ADDRESS,
			       info->attrs[DRBD2_A_CONTEXT],
			       drbd2_context_nl_policy, info->extack);
	if (err)
		return err;

	if (tb[DRBD2_A_CONTEXT_MINOR])
		ctx->minor = nla_get_u32(tb[DRBD2_A_CONTEXT_MINOR]);
	if (tb[DRBD2_A_CONTEXT_VOLUME])
		ctx->volume = nla_get_u32(tb[DRBD2_A_CONTEXT_VOLUME]);
	if (tb[DRBD2_A_CONTEXT_PEER_NODE_ID])
		ctx->peer_node_id = nla_get_u32(tb[DRBD2_A_CONTEXT_PEER_NODE_ID]);
	if (tb[DRBD2_A_CONTEXT_RESOURCE_NAME])
		ctx->resource_name = nla_data(tb[DRBD2_A_CONTEXT_RESOURCE_NAME]);
	return 0;
}

/*
 * Allocates the command context together with the drbd2 request state,
 * stores it in info->user_ptr[0], prepares the reply message and resolves
 * the objects the command refers to. A failure here means post_doit is
 * not called, so everything is cleaned up before returning.
 */
int drbd2_pre_doit(const struct genl_split_ops *ops, struct sk_buff *skb,
		   struct genl_info *info)
{
	const u8 cmd = info->genlhdr->cmd;
	struct drbd_adm_ctx *adm_ctx;
	struct drbd2_ctx *dctx;
	struct drbd2_req *req;
	unsigned int flags;
	int err;

	/*
	 * genl_rcv_msg() checked CAP_NET_ADMIN for the commands with the
	 * admin-perm flag; as in the legacy family, configuring DRBD also
	 * requires CAP_SYS_ADMIN.
	 */
	if ((ops->flags & GENL_ADMIN_PERM) && !capable(CAP_SYS_ADMIN)) {
		GENL_SET_ERR_MSG(info, "CAP_SYS_ADMIN required");
		return -EPERM;
	}

	dctx = kzalloc_obj(struct drbd2_ctx);
	if (!dctx)
		return -ENOMEM;

	adm_ctx = &dctx->ctx;
	req = &dctx->req;
	adm_ctx->d = &drbd2_dialect;
	adm_ctx->req = req;
	adm_ctx->result = NO_ERROR;
	adm_ctx->net = sock_net(skb->sk);
	/*
	 * Only the *-set commands accept set-defaults; genl sizes info->attrs
	 * to the maxattr of the command, so do not index past it elsewhere.
	 */
	adm_ctx->set_defaults = ops->maxattr >= DRBD2_A_SET_DEFAULTS &&
				info->attrs[DRBD2_A_SET_DEFAULTS];
	req->info = info;

	err = drbd2_parse_context(adm_ctx, info);
	if (err)
		goto fail;

	req->reply_skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!req->reply_skb) {
		err = -ENOMEM;
		goto fail;
	}
	req->reply_hdr = genlmsg_put_reply(req->reply_skb, info,
					   &drbd2_nl_family, 0, cmd);
	if (!req->reply_hdr) {
		err = -EMSGSIZE;
		goto fail;
	}

	flags = cmd < ARRAY_SIZE(drbd2_cmd_flags) ? drbd2_cmd_flags[cmd] : 0;
	if (drbd_adm_ctx_resolve(adm_ctx, flags) != NO_ERROR) {
		err = drbd2_errno(adm_ctx->result);
		drbd2_set_extack(info, adm_ctx);
		drbd_adm_ctx_release(adm_ctx);
		goto fail;
	}

	info->user_ptr[0] = adm_ctx;
	return 0;

fail:
	nlmsg_free(req->reply_skb);
	kfree(dctx);
	info->user_ptr[0] = NULL;
	return err;
}

/*
 * Sends the reply, drops the references acquired while resolving, and
 * frees the context. The reply is gone when the command failed with an
 * ERR_* code; the errno and the extended ACK describe that instead.
 */
void drbd2_post_doit(const struct genl_split_ops *ops, struct sk_buff *skb,
		     struct genl_info *info)
{
	struct drbd_adm_ctx *adm_ctx = info->user_ptr[0];
	struct drbd2_req *req;

	if (!adm_ctx)
		return;

	req = drbd2_req(adm_ctx);
	if (req->reply_skb) {
		drbd2_put_outcome(adm_ctx);
		genlmsg_end(req->reply_skb, req->reply_hdr);
		if (genlmsg_reply(req->reply_skb, info))
			pr_err("error sending genl reply\n");
	}

	drbd_adm_ctx_release(adm_ctx);
	kfree(container_of(adm_ctx, struct drbd2_ctx, ctx));
}

/*
 * The attribute sets of a request.
 */

static bool drbd2_has_set(struct drbd_adm_ctx *ctx, enum drbd_nl_attr_set set)
{
	static const u16 tla[__DRBD_NL_SET_MAX] = {
		[DRBD_NL_SET_DISK_CONF]			= DRBD2_A_DISK_CONF,
		[DRBD_NL_SET_NET_CONF]			= DRBD2_A_NET_CONF,
		[DRBD_NL_SET_RES_OPTS]			= DRBD2_A_RESOURCE_OPTS,
		[DRBD_NL_SET_PEER_DEVICE_CONF]		= DRBD2_A_PEER_DEVICE_CONF,
		[DRBD_NL_SET_DEVICE_CONF]		= DRBD2_A_DEVICE_CONF,
		[DRBD_NL_SET_SET_ROLE_PARMS]		= DRBD2_A_SET_ROLE_PARMS,
		[DRBD_NL_SET_RESIZE_PARMS]		= DRBD2_A_RESIZE_PARMS,
		[DRBD_NL_SET_START_OV_PARMS]		= DRBD2_A_START_OV_PARMS,
		[DRBD_NL_SET_NEW_C_UUID_PARMS]		= DRBD2_A_NEW_CURRENT_UUID_PARMS,
		[DRBD_NL_SET_DISCONNECT_PARMS]		= DRBD2_A_DISCONNECT_PARMS,
		[DRBD_NL_SET_DETACH_PARMS]		= DRBD2_A_DETACH_PARMS,
		[DRBD_NL_SET_INVALIDATE_PARMS]		= DRBD2_A_INVALIDATE_PARMS,
		[DRBD_NL_SET_INVALIDATE_PEER_PARMS]	= DRBD2_A_INVALIDATE_PEER_PARMS,
		[DRBD_NL_SET_CONNECT_PARMS]		= DRBD2_A_CONNECT_PARMS,
		[DRBD_NL_SET_RENAME_RESOURCE_PARMS]	= DRBD2_A_RENAME_PARMS,
		[DRBD_NL_SET_SUSPEND_IO_PARMS]		= DRBD2_A_SUSPEND_IO_PARMS,
		/* both are carried by the context nest of the request */
		[DRBD_NL_SET_FORGET_PEER_PARMS]		= DRBD2_A_CONTEXT,
		[DRBD_NL_SET_PATH_PARMS]		= DRBD2_A_CONTEXT,
	};

	return drbd2_req(ctx)->info->attrs[tla[set]] != NULL;
}

/*
 * Parse the nest of "attrtype" into "tb". Returns -ENOMSG when the nest
 * is not part of the request at all, which is what the core expects for
 * a missing parameter set.
 */
static int drbd2_parse_set(struct drbd_adm_ctx *ctx, int attrtype, int maxtype,
			   const struct nla_policy *policy, struct nlattr **tb)
{
	struct genl_info *info = drbd2_req(ctx)->info;

	if (!info->attrs[attrtype])
		return -ENOMSG;
	return nla_parse_nested(tb, maxtype, info->attrs[attrtype], policy,
				info->extack);
}

#define DRBD2_PARSE_SET(ctx, name, NAME, tb)				\
	drbd2_parse_set((ctx), DRBD2_A_##NAME, ARRAY_SIZE(tb) - 1,	\
			drbd2_##name##_nl_policy, (tb))

static int drbd2_overlay_disk_conf(struct drbd_adm_ctx *ctx, struct disk_conf *s)
{
	struct nlattr *tb[DRBD2_A_DISK_CONF_BITMAP + 1];
	int err;

	err = DRBD2_PARSE_SET(ctx, disk_conf, DISK_CONF, tb);
	if (err)
		return err;

	/* the three attributes that describe the disk itself are required */
	if (!tb[DRBD2_A_DISK_CONF_BACKING_DEV] || !tb[DRBD2_A_DISK_CONF_META_DEV] ||
	    !tb[DRBD2_A_DISK_CONF_META_DEV_IDX])
		err = -ENOMSG;

	if (tb[DRBD2_A_DISK_CONF_BACKING_DEV])
		s->backing_dev_len = nla_strscpy(s->backing_dev,
						 tb[DRBD2_A_DISK_CONF_BACKING_DEV],
						 sizeof(s->backing_dev));
	if (tb[DRBD2_A_DISK_CONF_META_DEV])
		s->meta_dev_len = nla_strscpy(s->meta_dev, tb[DRBD2_A_DISK_CONF_META_DEV],
					      sizeof(s->meta_dev));
	if (tb[DRBD2_A_DISK_CONF_META_DEV_IDX])
		s->meta_dev_idx = nla_get_s32(tb[DRBD2_A_DISK_CONF_META_DEV_IDX]);
	if (tb[DRBD2_A_DISK_CONF_SIZE])
		s->disk_size = nla_get_u64(tb[DRBD2_A_DISK_CONF_SIZE]);
	if (tb[DRBD2_A_DISK_CONF_ON_IO_ERROR])
		s->on_io_error = nla_get_u32(tb[DRBD2_A_DISK_CONF_ON_IO_ERROR]);
	if (tb[DRBD2_A_DISK_CONF_RESYNC_AFTER])
		s->resync_after = nla_get_s32(tb[DRBD2_A_DISK_CONF_RESYNC_AFTER]);
	if (tb[DRBD2_A_DISK_CONF_AL_EXTENTS])
		s->al_extents = nla_get_u32(tb[DRBD2_A_DISK_CONF_AL_EXTENTS]);
	if (tb[DRBD2_A_DISK_CONF_DISK_BARRIER])
		s->disk_barrier = nla_get_u8(tb[DRBD2_A_DISK_CONF_DISK_BARRIER]);
	if (tb[DRBD2_A_DISK_CONF_DISK_FLUSHES])
		s->disk_flushes = nla_get_u8(tb[DRBD2_A_DISK_CONF_DISK_FLUSHES]);
	if (tb[DRBD2_A_DISK_CONF_DISK_DRAIN])
		s->disk_drain = nla_get_u8(tb[DRBD2_A_DISK_CONF_DISK_DRAIN]);
	if (tb[DRBD2_A_DISK_CONF_MD_FLUSHES])
		s->md_flushes = nla_get_u8(tb[DRBD2_A_DISK_CONF_MD_FLUSHES]);
	if (tb[DRBD2_A_DISK_CONF_DISK_TIMEOUT])
		s->disk_timeout = nla_get_u32(tb[DRBD2_A_DISK_CONF_DISK_TIMEOUT]);
	if (tb[DRBD2_A_DISK_CONF_READ_BALANCING])
		s->read_balancing = nla_get_u32(tb[DRBD2_A_DISK_CONF_READ_BALANCING]);
	if (tb[DRBD2_A_DISK_CONF_UNPLUG_WATERMARK])
		s->unplug_watermark = nla_get_u32(tb[DRBD2_A_DISK_CONF_UNPLUG_WATERMARK]);
	if (tb[DRBD2_A_DISK_CONF_RS_DISCARD_GRANULARITY])
		s->rs_discard_granularity =
			nla_get_u32(tb[DRBD2_A_DISK_CONF_RS_DISCARD_GRANULARITY]);
	if (tb[DRBD2_A_DISK_CONF_AL_UPDATES])
		s->al_updates = nla_get_u8(tb[DRBD2_A_DISK_CONF_AL_UPDATES]);
	if (tb[DRBD2_A_DISK_CONF_DISCARD_ZEROES_IF_ALIGNED])
		s->discard_zeroes_if_aligned =
			nla_get_u8(tb[DRBD2_A_DISK_CONF_DISCARD_ZEROES_IF_ALIGNED]);
	if (tb[DRBD2_A_DISK_CONF_DISABLE_WRITE_SAME])
		s->disable_write_same = nla_get_u8(tb[DRBD2_A_DISK_CONF_DISABLE_WRITE_SAME]);
	if (tb[DRBD2_A_DISK_CONF_BITMAP])
		s->d_bitmap = nla_get_u8(tb[DRBD2_A_DISK_CONF_BITMAP]);
	return err;
}

static int drbd2_overlay_res_opts(struct drbd_adm_ctx *ctx, struct res_opts *s)
{
	struct nlattr *tb[DRBD2_A_RESOURCE_OPTS_EXPLICIT_DRBD8_COMPAT + 1];
	int err;

	err = DRBD2_PARSE_SET(ctx, resource_opts, RESOURCE_OPTS, tb);
	if (err)
		return err;

	/* the node id identifies this node in the resource; it is required */
	if (!tb[DRBD2_A_RESOURCE_OPTS_NODE_ID])
		err = -ENOMSG;

	if (tb[DRBD2_A_RESOURCE_OPTS_CPU_MASK])
		s->cpu_mask_len = nla_strscpy(s->cpu_mask, tb[DRBD2_A_RESOURCE_OPTS_CPU_MASK],
					      sizeof(s->cpu_mask));
	if (tb[DRBD2_A_RESOURCE_OPTS_ON_NO_DATA_ACCESSIBLE])
		s->on_no_data = nla_get_u32(tb[DRBD2_A_RESOURCE_OPTS_ON_NO_DATA_ACCESSIBLE]);
	if (tb[DRBD2_A_RESOURCE_OPTS_AUTO_PROMOTE])
		s->auto_promote = nla_get_u8(tb[DRBD2_A_RESOURCE_OPTS_AUTO_PROMOTE]);
	if (tb[DRBD2_A_RESOURCE_OPTS_NODE_ID])
		s->node_id = nla_get_u32(tb[DRBD2_A_RESOURCE_OPTS_NODE_ID]);
	if (tb[DRBD2_A_RESOURCE_OPTS_PEER_ACK_WINDOW])
		s->peer_ack_window = nla_get_u32(tb[DRBD2_A_RESOURCE_OPTS_PEER_ACK_WINDOW]);
	if (tb[DRBD2_A_RESOURCE_OPTS_TWOPC_TIMEOUT])
		s->twopc_timeout = nla_get_u32(tb[DRBD2_A_RESOURCE_OPTS_TWOPC_TIMEOUT]);
	if (tb[DRBD2_A_RESOURCE_OPTS_TWOPC_RETRY_TIMEOUT])
		s->twopc_retry_timeout =
			nla_get_u32(tb[DRBD2_A_RESOURCE_OPTS_TWOPC_RETRY_TIMEOUT]);
	if (tb[DRBD2_A_RESOURCE_OPTS_PEER_ACK_DELAY])
		s->peer_ack_delay = nla_get_u32(tb[DRBD2_A_RESOURCE_OPTS_PEER_ACK_DELAY]);
	if (tb[DRBD2_A_RESOURCE_OPTS_AUTO_PROMOTE_TIMEOUT])
		s->auto_promote_timeout =
			nla_get_u32(tb[DRBD2_A_RESOURCE_OPTS_AUTO_PROMOTE_TIMEOUT]);
	if (tb[DRBD2_A_RESOURCE_OPTS_MAX_IO_DEPTH])
		s->nr_requests = nla_get_u32(tb[DRBD2_A_RESOURCE_OPTS_MAX_IO_DEPTH]);
	if (tb[DRBD2_A_RESOURCE_OPTS_QUORUM])
		s->quorum = nla_get_s32(tb[DRBD2_A_RESOURCE_OPTS_QUORUM]);
	if (tb[DRBD2_A_RESOURCE_OPTS_ON_NO_QUORUM])
		s->on_no_quorum = nla_get_u32(tb[DRBD2_A_RESOURCE_OPTS_ON_NO_QUORUM]);
	if (tb[DRBD2_A_RESOURCE_OPTS_QUORUM_MIN_REDUNDANCY])
		s->quorum_min_redundancy =
			nla_get_s32(tb[DRBD2_A_RESOURCE_OPTS_QUORUM_MIN_REDUNDANCY]);
	if (tb[DRBD2_A_RESOURCE_OPTS_ON_SUSPENDED_PRIMARY_OUTDATED])
		s->on_susp_primary_outdated =
			nla_get_u32(tb[DRBD2_A_RESOURCE_OPTS_ON_SUSPENDED_PRIMARY_OUTDATED]);
	if (tb[DRBD2_A_RESOURCE_OPTS_DRBD8_COMPAT_MODE])
		s->drbd8_compat_mode = nla_get_u8(tb[DRBD2_A_RESOURCE_OPTS_DRBD8_COMPAT_MODE]);
	if (tb[DRBD2_A_RESOURCE_OPTS_EXPLICIT_DRBD8_COMPAT])
		s->explicit_drbd8_compat =
			nla_get_u8(tb[DRBD2_A_RESOURCE_OPTS_EXPLICIT_DRBD8_COMPAT]);
	return err;
}

static int drbd2_overlay_net_conf(struct drbd_adm_ctx *ctx, struct net_conf *s)
{
	struct nlattr *tb[DRBD2_A_NET_CONF_RDMA_CTRL_SNDBUF_SIZE + 1];
	int err;

	err = DRBD2_PARSE_SET(ctx, net_conf, NET_CONF, tb);
	if (err)
		return err;

	if (tb[DRBD2_A_NET_CONF_SHARED_SECRET])
		s->shared_secret_len = nla_strscpy(s->shared_secret,
						   tb[DRBD2_A_NET_CONF_SHARED_SECRET],
						   sizeof(s->shared_secret));
	if (tb[DRBD2_A_NET_CONF_CRAM_HMAC_ALG])
		s->cram_hmac_alg_len = nla_strscpy(s->cram_hmac_alg,
						   tb[DRBD2_A_NET_CONF_CRAM_HMAC_ALG],
						   sizeof(s->cram_hmac_alg));
	if (tb[DRBD2_A_NET_CONF_INTEGRITY_ALG])
		s->integrity_alg_len = nla_strscpy(s->integrity_alg,
						   tb[DRBD2_A_NET_CONF_INTEGRITY_ALG],
						   sizeof(s->integrity_alg));
	if (tb[DRBD2_A_NET_CONF_VERIFY_ALG])
		s->verify_alg_len = nla_strscpy(s->verify_alg,
						tb[DRBD2_A_NET_CONF_VERIFY_ALG],
						sizeof(s->verify_alg));
	if (tb[DRBD2_A_NET_CONF_CSUMS_ALG])
		s->csums_alg_len = nla_strscpy(s->csums_alg, tb[DRBD2_A_NET_CONF_CSUMS_ALG],
					       sizeof(s->csums_alg));
	if (tb[DRBD2_A_NET_CONF_PROTOCOL])
		s->wire_protocol = nla_get_u32(tb[DRBD2_A_NET_CONF_PROTOCOL]);
	if (tb[DRBD2_A_NET_CONF_CONNECT_INT])
		s->connect_int = nla_get_u32(tb[DRBD2_A_NET_CONF_CONNECT_INT]);
	if (tb[DRBD2_A_NET_CONF_TIMEOUT])
		s->timeout = nla_get_u32(tb[DRBD2_A_NET_CONF_TIMEOUT]);
	if (tb[DRBD2_A_NET_CONF_PING_INT])
		s->ping_int = nla_get_u32(tb[DRBD2_A_NET_CONF_PING_INT]);
	if (tb[DRBD2_A_NET_CONF_PING_TIMEO])
		s->ping_timeo = nla_get_u32(tb[DRBD2_A_NET_CONF_PING_TIMEO]);
	if (tb[DRBD2_A_NET_CONF_SNDBUF_SIZE])
		s->sndbuf_size = nla_get_u32(tb[DRBD2_A_NET_CONF_SNDBUF_SIZE]);
	if (tb[DRBD2_A_NET_CONF_RCVBUF_SIZE])
		s->rcvbuf_size = nla_get_u32(tb[DRBD2_A_NET_CONF_RCVBUF_SIZE]);
	if (tb[DRBD2_A_NET_CONF_KO_COUNT])
		s->ko_count = nla_get_u32(tb[DRBD2_A_NET_CONF_KO_COUNT]);
	if (tb[DRBD2_A_NET_CONF_MAX_EPOCH_SIZE])
		s->max_epoch_size = nla_get_u32(tb[DRBD2_A_NET_CONF_MAX_EPOCH_SIZE]);
	if (tb[DRBD2_A_NET_CONF_AFTER_SB_0PRI])
		s->after_sb_0p = nla_get_u32(tb[DRBD2_A_NET_CONF_AFTER_SB_0PRI]);
	if (tb[DRBD2_A_NET_CONF_AFTER_SB_1PRI])
		s->after_sb_1p = nla_get_u32(tb[DRBD2_A_NET_CONF_AFTER_SB_1PRI]);
	if (tb[DRBD2_A_NET_CONF_AFTER_SB_2PRI])
		s->after_sb_2p = nla_get_u32(tb[DRBD2_A_NET_CONF_AFTER_SB_2PRI]);
	if (tb[DRBD2_A_NET_CONF_RR_CONFLICT])
		s->rr_conflict = nla_get_u32(tb[DRBD2_A_NET_CONF_RR_CONFLICT]);
	if (tb[DRBD2_A_NET_CONF_ON_CONGESTION])
		s->on_congestion = nla_get_u32(tb[DRBD2_A_NET_CONF_ON_CONGESTION]);
	if (tb[DRBD2_A_NET_CONF_CONG_FILL])
		s->cong_fill = nla_get_u32(tb[DRBD2_A_NET_CONF_CONG_FILL]);
	if (tb[DRBD2_A_NET_CONF_CONG_EXTENTS])
		s->cong_extents = nla_get_u32(tb[DRBD2_A_NET_CONF_CONG_EXTENTS]);
	if (tb[DRBD2_A_NET_CONF_TWO_PRIMARIES])
		s->two_primaries = nla_get_u8(tb[DRBD2_A_NET_CONF_TWO_PRIMARIES]);
	if (tb[DRBD2_A_NET_CONF_TCP_CORK])
		s->tcp_cork = nla_get_u8(tb[DRBD2_A_NET_CONF_TCP_CORK]);
	if (tb[DRBD2_A_NET_CONF_ALWAYS_ASBP])
		s->always_asbp = nla_get_u8(tb[DRBD2_A_NET_CONF_ALWAYS_ASBP]);
	if (tb[DRBD2_A_NET_CONF_USE_RLE])
		s->use_rle = nla_get_u8(tb[DRBD2_A_NET_CONF_USE_RLE]);
	if (tb[DRBD2_A_NET_CONF_FENCING])
		s->fencing_policy = nla_get_u32(tb[DRBD2_A_NET_CONF_FENCING]);
	if (tb[DRBD2_A_NET_CONF_CONNECTION_NAME])
		s->name_len = nla_strscpy(s->name, tb[DRBD2_A_NET_CONF_CONNECTION_NAME],
					  sizeof(s->name));
	if (tb[DRBD2_A_NET_CONF_CSUMS_AFTER_CRASH_ONLY])
		s->csums_after_crash_only =
			nla_get_u8(tb[DRBD2_A_NET_CONF_CSUMS_AFTER_CRASH_ONLY]);
	if (tb[DRBD2_A_NET_CONF_SOCK_CHECK_TIMEO])
		s->sock_check_timeo = nla_get_u32(tb[DRBD2_A_NET_CONF_SOCK_CHECK_TIMEO]);
	if (tb[DRBD2_A_NET_CONF_TRANSPORT_NAME])
		s->transport_name_len = nla_strscpy(s->transport_name,
						    tb[DRBD2_A_NET_CONF_TRANSPORT_NAME],
						    sizeof(s->transport_name));
	if (tb[DRBD2_A_NET_CONF_MAX_BUFFERS])
		s->max_buffers = nla_get_u32(tb[DRBD2_A_NET_CONF_MAX_BUFFERS]);
	if (tb[DRBD2_A_NET_CONF_ALLOW_REMOTE_READ])
		s->allow_remote_read = nla_get_u8(tb[DRBD2_A_NET_CONF_ALLOW_REMOTE_READ]);
	if (tb[DRBD2_A_NET_CONF_TLS])
		s->tls = nla_get_u8(tb[DRBD2_A_NET_CONF_TLS]);
	if (tb[DRBD2_A_NET_CONF_TLS_PRIVKEY])
		s->tls_privkey = nla_get_s32(tb[DRBD2_A_NET_CONF_TLS_PRIVKEY]);
	if (tb[DRBD2_A_NET_CONF_TLS_CERTIFICATE])
		s->tls_certificate = nla_get_s32(tb[DRBD2_A_NET_CONF_TLS_CERTIFICATE]);
	if (tb[DRBD2_A_NET_CONF_TLS_KEYRING])
		s->tls_keyring = nla_get_s32(tb[DRBD2_A_NET_CONF_TLS_KEYRING]);
	if (tb[DRBD2_A_NET_CONF_LOAD_BALANCE_PATHS])
		s->load_balance_paths = nla_get_u8(tb[DRBD2_A_NET_CONF_LOAD_BALANCE_PATHS]);
	if (tb[DRBD2_A_NET_CONF_RDMA_CTRL_RCVBUF_SIZE])
		s->rdma_ctrl_rcvbuf_size =
			nla_get_u32(tb[DRBD2_A_NET_CONF_RDMA_CTRL_RCVBUF_SIZE]);
	if (tb[DRBD2_A_NET_CONF_RDMA_CTRL_SNDBUF_SIZE])
		s->rdma_ctrl_sndbuf_size =
			nla_get_u32(tb[DRBD2_A_NET_CONF_RDMA_CTRL_SNDBUF_SIZE]);
	return 0;
}

static int drbd2_overlay_peer_device_conf(struct drbd_adm_ctx *ctx,
					  struct peer_device_conf *s)
{
	struct nlattr *tb[DRBD2_A_PEER_DEVICE_CONF_PEER_TIEBREAKER + 1];
	int err;

	err = DRBD2_PARSE_SET(ctx, peer_device_conf, PEER_DEVICE_CONF, tb);
	if (err)
		return err;

	if (tb[DRBD2_A_PEER_DEVICE_CONF_RESYNC_RATE])
		s->resync_rate = nla_get_u32(tb[DRBD2_A_PEER_DEVICE_CONF_RESYNC_RATE]);
	if (tb[DRBD2_A_PEER_DEVICE_CONF_C_PLAN_AHEAD])
		s->c_plan_ahead = nla_get_u32(tb[DRBD2_A_PEER_DEVICE_CONF_C_PLAN_AHEAD]);
	if (tb[DRBD2_A_PEER_DEVICE_CONF_C_DELAY_TARGET])
		s->c_delay_target = nla_get_u32(tb[DRBD2_A_PEER_DEVICE_CONF_C_DELAY_TARGET]);
	if (tb[DRBD2_A_PEER_DEVICE_CONF_C_FILL_TARGET])
		s->c_fill_target = nla_get_u32(tb[DRBD2_A_PEER_DEVICE_CONF_C_FILL_TARGET]);
	if (tb[DRBD2_A_PEER_DEVICE_CONF_C_MAX_RATE])
		s->c_max_rate = nla_get_u32(tb[DRBD2_A_PEER_DEVICE_CONF_C_MAX_RATE]);
	if (tb[DRBD2_A_PEER_DEVICE_CONF_C_MIN_RATE])
		s->c_min_rate = nla_get_u32(tb[DRBD2_A_PEER_DEVICE_CONF_C_MIN_RATE]);
	if (tb[DRBD2_A_PEER_DEVICE_CONF_BITMAP])
		s->bitmap = nla_get_u8(tb[DRBD2_A_PEER_DEVICE_CONF_BITMAP]);
	if (tb[DRBD2_A_PEER_DEVICE_CONF_RESYNC_WITHOUT_REPLICATION])
		s->resync_without_replication =
			nla_get_u8(tb[DRBD2_A_PEER_DEVICE_CONF_RESYNC_WITHOUT_REPLICATION]);
	if (tb[DRBD2_A_PEER_DEVICE_CONF_PEER_TIEBREAKER])
		s->peer_tiebreaker = nla_get_u8(tb[DRBD2_A_PEER_DEVICE_CONF_PEER_TIEBREAKER]);
	return 0;
}

static int drbd2_overlay_device_conf(struct drbd_adm_ctx *ctx, struct device_conf *s)
{
	struct nlattr *tb[DRBD2_A_DEVICE_CONF_DISCARD_GRANULARITY + 1];
	int err;

	err = DRBD2_PARSE_SET(ctx, device_conf, DEVICE_CONF, tb);
	if (err)
		return err;

	if (tb[DRBD2_A_DEVICE_CONF_MAX_BIO_SIZE])
		s->max_bio_size = nla_get_u32(tb[DRBD2_A_DEVICE_CONF_MAX_BIO_SIZE]);
	if (tb[DRBD2_A_DEVICE_CONF_INTENTIONAL_DISKLESS])
		s->intentional_diskless =
			nla_get_u8(tb[DRBD2_A_DEVICE_CONF_INTENTIONAL_DISKLESS]);
	if (tb[DRBD2_A_DEVICE_CONF_BLOCK_SIZE])
		s->block_size = nla_get_u32(tb[DRBD2_A_DEVICE_CONF_BLOCK_SIZE]);
	if (tb[DRBD2_A_DEVICE_CONF_DISCARD_GRANULARITY])
		s->discard_granularity =
			nla_get_u32(tb[DRBD2_A_DEVICE_CONF_DISCARD_GRANULARITY]);
	return 0;
}

static int drbd2_overlay_set_role_parms(struct drbd_adm_ctx *ctx, struct set_role_parms *s)
{
	struct nlattr *tb[DRBD2_A_SET_ROLE_PARMS_FORCE + 1];
	int err;

	err = DRBD2_PARSE_SET(ctx, set_role_parms, SET_ROLE_PARMS, tb);
	if (err)
		return err;

	s->force = !!tb[DRBD2_A_SET_ROLE_PARMS_FORCE];
	return 0;
}

static int drbd2_overlay_resize_parms(struct drbd_adm_ctx *ctx, struct resize_parms *s)
{
	struct nlattr *tb[DRBD2_A_RESIZE_PARMS_AL_STRIPE_SIZE + 1];
	int err;

	err = DRBD2_PARSE_SET(ctx, resize_parms, RESIZE_PARMS, tb);
	if (err)
		return err;

	if (tb[DRBD2_A_RESIZE_PARMS_SIZE])
		s->resize_size = nla_get_u64(tb[DRBD2_A_RESIZE_PARMS_SIZE]);
	s->resize_force = !!tb[DRBD2_A_RESIZE_PARMS_ASSUME_PEER_HAS_SPACE];
	s->no_resync = !!tb[DRBD2_A_RESIZE_PARMS_ASSUME_CLEAN];
	if (tb[DRBD2_A_RESIZE_PARMS_AL_STRIPES])
		s->al_stripes = nla_get_u32(tb[DRBD2_A_RESIZE_PARMS_AL_STRIPES]);
	if (tb[DRBD2_A_RESIZE_PARMS_AL_STRIPE_SIZE])
		s->al_stripe_size = nla_get_u32(tb[DRBD2_A_RESIZE_PARMS_AL_STRIPE_SIZE]);
	return 0;
}

static int drbd2_overlay_start_ov_parms(struct drbd_adm_ctx *ctx, struct start_ov_parms *s)
{
	struct nlattr *tb[DRBD2_A_START_OV_PARMS_STOP_SECTOR + 1];
	int err;

	err = DRBD2_PARSE_SET(ctx, start_ov_parms, START_OV_PARMS, tb);
	if (err)
		return err;

	if (tb[DRBD2_A_START_OV_PARMS_START_SECTOR])
		s->ov_start_sector = nla_get_u64(tb[DRBD2_A_START_OV_PARMS_START_SECTOR]);
	if (tb[DRBD2_A_START_OV_PARMS_STOP_SECTOR])
		s->ov_stop_sector = nla_get_u64(tb[DRBD2_A_START_OV_PARMS_STOP_SECTOR]);
	return 0;
}

static int drbd2_overlay_new_c_uuid_parms(struct drbd_adm_ctx *ctx,
					  struct new_c_uuid_parms *s)
{
	struct nlattr *tb[DRBD2_A_NEW_CURRENT_UUID_PARMS_FORCE_RESYNC + 1];
	int err;

	err = DRBD2_PARSE_SET(ctx, new_current_uuid_parms, NEW_CURRENT_UUID_PARMS, tb);
	if (err)
		return err;

	s->clear_bm = !!tb[DRBD2_A_NEW_CURRENT_UUID_PARMS_CLEAR_BM];
	s->force_resync = !!tb[DRBD2_A_NEW_CURRENT_UUID_PARMS_FORCE_RESYNC];
	return 0;
}

static int drbd2_overlay_disconnect_parms(struct drbd_adm_ctx *ctx,
					  struct disconnect_parms *s)
{
	struct nlattr *tb[DRBD2_A_DISCONNECT_PARMS_FORCE + 1];
	int err;

	err = DRBD2_PARSE_SET(ctx, disconnect_parms, DISCONNECT_PARMS, tb);
	if (err)
		return err;

	s->force_disconnect = !!tb[DRBD2_A_DISCONNECT_PARMS_FORCE];
	return 0;
}

static int drbd2_overlay_detach_parms(struct drbd_adm_ctx *ctx, struct detach_parms *s)
{
	struct nlattr *tb[DRBD2_A_DETACH_PARMS_INTENTIONAL_DISKLESS_DETACH + 1];
	int err;

	err = DRBD2_PARSE_SET(ctx, detach_parms, DETACH_PARMS, tb);
	if (err)
		return err;

	s->force_detach = !!tb[DRBD2_A_DETACH_PARMS_FORCE];
	s->intentional_diskless_detach =
		!!tb[DRBD2_A_DETACH_PARMS_INTENTIONAL_DISKLESS_DETACH];
	return 0;
}

static int drbd2_overlay_invalidate_parms(struct drbd_adm_ctx *ctx,
					  struct invalidate_parms *s)
{
	struct nlattr *tb[DRBD2_A_INVALIDATE_PARMS_RESET_BITMAP + 1];
	int err;

	err = DRBD2_PARSE_SET(ctx, invalidate_parms, INVALIDATE_PARMS, tb);
	if (err)
		return err;

	if (tb[DRBD2_A_INVALIDATE_PARMS_SYNC_FROM_PEER_NODE_ID])
		s->sync_from_peer_node_id =
			nla_get_u32(tb[DRBD2_A_INVALIDATE_PARMS_SYNC_FROM_PEER_NODE_ID]);
	if (tb[DRBD2_A_INVALIDATE_PARMS_RESET_BITMAP])
		s->reset_bitmap = nla_get_u8(tb[DRBD2_A_INVALIDATE_PARMS_RESET_BITMAP]);
	return 0;
}

static int drbd2_overlay_invalidate_peer_parms(struct drbd_adm_ctx *ctx,
					       struct invalidate_peer_parms *s)
{
	struct nlattr *tb[DRBD2_A_INVALIDATE_PEER_PARMS_RESET_BITMAP + 1];
	int err;

	err = DRBD2_PARSE_SET(ctx, invalidate_peer_parms, INVALIDATE_PEER_PARMS, tb);
	if (err)
		return err;

	if (tb[DRBD2_A_INVALIDATE_PEER_PARMS_RESET_BITMAP])
		s->p_reset_bitmap =
			nla_get_u8(tb[DRBD2_A_INVALIDATE_PEER_PARMS_RESET_BITMAP]);
	return 0;
}

/*
 * connection-forget names the peer in the context of the request, not in
 * a parameter set of its own.
 */
static int drbd2_overlay_forget_peer_parms(struct drbd_adm_ctx *ctx,
					   struct forget_peer_parms *s)
{
	if (ctx->peer_node_id == PEER_NODE_ID_UNSPECIFIED)
		return -ENOMSG;
	s->forget_peer_node_id = ctx->peer_node_id;
	return 0;
}

static int drbd2_overlay_connect_parms(struct drbd_adm_ctx *ctx, struct connect_parms *s)
{
	struct nlattr *tb[DRBD2_A_CONNECT_PARMS_DISCARD_MY_DATA + 1];
	int err;

	err = DRBD2_PARSE_SET(ctx, connect_parms, CONNECT_PARMS, tb);
	if (err)
		return err;

	s->tentative = !!tb[DRBD2_A_CONNECT_PARMS_TENTATIVE];
	s->discard_my_data = !!tb[DRBD2_A_CONNECT_PARMS_DISCARD_MY_DATA];
	return 0;
}

/*
 * A path is identified by the two addresses in the context of the
 * request; both are required.
 */
static int drbd2_overlay_path_parms(struct drbd_adm_ctx *ctx, struct path_parms *s)
{
	struct nlattr *tb[DRBD2_A_CONTEXT_PEER_ADDRESS + 1];
	struct genl_info *info = drbd2_req(ctx)->info;
	int err;

	if (!info->attrs[DRBD2_A_CONTEXT])
		return -ENOMSG;
	err = nla_parse_nested(tb, DRBD2_A_CONTEXT_PEER_ADDRESS,
			       info->attrs[DRBD2_A_CONTEXT],
			       drbd2_context_nl_policy, info->extack);
	if (err)
		return err;
	if (!tb[DRBD2_A_CONTEXT_MY_ADDRESS] || !tb[DRBD2_A_CONTEXT_PEER_ADDRESS])
		return -ENOMSG;

	err = drbd2_get_address(tb[DRBD2_A_CONTEXT_MY_ADDRESS], s->my_addr, &s->my_addr_len);
	if (err)
		return err;
	return drbd2_get_address(tb[DRBD2_A_CONTEXT_PEER_ADDRESS],
				 s->peer_addr, &s->peer_addr_len);
}

static int drbd2_overlay_rename_resource_parms(struct drbd_adm_ctx *ctx,
					       struct rename_resource_parms *s)
{
	struct nlattr *tb[DRBD2_A_RENAME_PARMS_NEW_NAME + 1];
	int err;

	err = DRBD2_PARSE_SET(ctx, rename_parms, RENAME_PARMS, tb);
	if (err)
		return err;
	if (!tb[DRBD2_A_RENAME_PARMS_NEW_NAME])
		return -ENOMSG;

	s->new_resource_name_len = nla_strscpy(s->new_resource_name,
					       tb[DRBD2_A_RENAME_PARMS_NEW_NAME],
					       sizeof(s->new_resource_name));
	return 0;
}

static int drbd2_overlay_suspend_io_parms(struct drbd_adm_ctx *ctx,
					  struct suspend_io_parms *s)
{
	struct nlattr *tb[DRBD2_A_SUSPEND_IO_PARMS_BDEV_FREEZE + 1];
	int err;

	err = DRBD2_PARSE_SET(ctx, suspend_io_parms, SUSPEND_IO_PARMS, tb);
	if (err)
		return err;

	if (tb[DRBD2_A_SUSPEND_IO_PARMS_BDEV_FREEZE])
		s->bdev_freeze = nla_get_u8(tb[DRBD2_A_SUSPEND_IO_PARMS_BDEV_FREEZE]);
	return 0;
}

static int drbd2_overlay(struct drbd_adm_ctx *ctx, enum drbd_nl_attr_set set, void *dst)
{
	switch (set) {
	case DRBD_NL_SET_DISK_CONF:		return drbd2_overlay_disk_conf(ctx, dst);
	case DRBD_NL_SET_NET_CONF:		return drbd2_overlay_net_conf(ctx, dst);
	case DRBD_NL_SET_RES_OPTS:		return drbd2_overlay_res_opts(ctx, dst);
	case DRBD_NL_SET_PEER_DEVICE_CONF:	return drbd2_overlay_peer_device_conf(ctx, dst);
	case DRBD_NL_SET_DEVICE_CONF:		return drbd2_overlay_device_conf(ctx, dst);
	case DRBD_NL_SET_SET_ROLE_PARMS:	return drbd2_overlay_set_role_parms(ctx, dst);
	case DRBD_NL_SET_RESIZE_PARMS:		return drbd2_overlay_resize_parms(ctx, dst);
	case DRBD_NL_SET_START_OV_PARMS:	return drbd2_overlay_start_ov_parms(ctx, dst);
	case DRBD_NL_SET_NEW_C_UUID_PARMS:	return drbd2_overlay_new_c_uuid_parms(ctx, dst);
	case DRBD_NL_SET_DISCONNECT_PARMS:	return drbd2_overlay_disconnect_parms(ctx, dst);
	case DRBD_NL_SET_DETACH_PARMS:		return drbd2_overlay_detach_parms(ctx, dst);
	case DRBD_NL_SET_INVALIDATE_PARMS:	return drbd2_overlay_invalidate_parms(ctx, dst);
	case DRBD_NL_SET_INVALIDATE_PEER_PARMS:
		return drbd2_overlay_invalidate_peer_parms(ctx, dst);
	case DRBD_NL_SET_FORGET_PEER_PARMS:	return drbd2_overlay_forget_peer_parms(ctx, dst);
	case DRBD_NL_SET_CONNECT_PARMS:		return drbd2_overlay_connect_parms(ctx, dst);
	case DRBD_NL_SET_PATH_PARMS:		return drbd2_overlay_path_parms(ctx, dst);
	case DRBD_NL_SET_RENAME_RESOURCE_PARMS:
		return drbd2_overlay_rename_resource_parms(ctx, dst);
	case DRBD_NL_SET_SUSPEND_IO_PARMS:	return drbd2_overlay_suspend_io_parms(ctx, dst);
	case __DRBD_NL_SET_MAX:
		break;
	}
	return -EINVAL;
}

/*
 * The core asks about one invariant field at a time and stops at the
 * first one that is present, so exactly one message is logged, for that
 * field. Parsing the nest per query keeps that short-circuit intact.
 */
static bool drbd2_attr_present(struct drbd_adm_ctx *ctx, enum drbd_adm_field field)
{
	static const struct {
		u16 tla;
		u16 maxtype;
		const struct nla_policy *policy;
		u16 attr;
		const char *name;
	} invariant[] = {
		[DRBD_ADM_F_DISK_BACKING_DEV] = { DRBD2_A_DISK_CONF,
			DRBD2_A_DISK_CONF_BITMAP, drbd2_disk_conf_nl_policy,
			DRBD2_A_DISK_CONF_BACKING_DEV, "disk-conf.backing-dev" },
		[DRBD_ADM_F_DISK_META_DEV] = { DRBD2_A_DISK_CONF,
			DRBD2_A_DISK_CONF_BITMAP, drbd2_disk_conf_nl_policy,
			DRBD2_A_DISK_CONF_META_DEV, "disk-conf.meta-dev" },
		[DRBD_ADM_F_DISK_META_DEV_IDX] = { DRBD2_A_DISK_CONF,
			DRBD2_A_DISK_CONF_BITMAP, drbd2_disk_conf_nl_policy,
			DRBD2_A_DISK_CONF_META_DEV_IDX, "disk-conf.meta-dev-idx" },
		[DRBD_ADM_F_DISK_SIZE] = { DRBD2_A_DISK_CONF,
			DRBD2_A_DISK_CONF_BITMAP, drbd2_disk_conf_nl_policy,
			DRBD2_A_DISK_CONF_SIZE, "disk-conf.size" },
		[DRBD_ADM_F_NET_TRANSPORT_NAME] = { DRBD2_A_NET_CONF,
			DRBD2_A_NET_CONF_RDMA_CTRL_SNDBUF_SIZE, drbd2_net_conf_nl_policy,
			DRBD2_A_NET_CONF_TRANSPORT_NAME, "net-conf.transport-name" },
		[DRBD_ADM_F_NET_LOAD_BALANCE_PATHS] = { DRBD2_A_NET_CONF,
			DRBD2_A_NET_CONF_RDMA_CTRL_SNDBUF_SIZE, drbd2_net_conf_nl_policy,
			DRBD2_A_NET_CONF_LOAD_BALANCE_PATHS, "net-conf.load-balance-paths" },
		[DRBD_ADM_F_RES_NODE_ID] = { DRBD2_A_RESOURCE_OPTS,
			DRBD2_A_RESOURCE_OPTS_EXPLICIT_DRBD8_COMPAT,
			drbd2_resource_opts_nl_policy,
			DRBD2_A_RESOURCE_OPTS_NODE_ID, "resource-opts.node-id" },
	};
	struct genl_info *info = drbd2_req(ctx)->info;
	struct nlattr **tb;
	bool found;

	if (!info->attrs[invariant[field].tla])
		return false;

	tb = kcalloc(invariant[field].maxtype + 1, sizeof(*tb), GFP_KERNEL);
	if (!tb)
		return false;
	found = !nla_parse_nested(tb, invariant[field].maxtype,
				  info->attrs[invariant[field].tla],
				  invariant[field].policy, NULL) &&
		tb[invariant[field].attr];
	kfree(tb);
	if (found)
		pr_info("must not change invariant attr: %s\n", invariant[field].name);
	return found;
}

static int drbd2_put_timeout_type(struct drbd_adm_ctx *ctx, enum drbd_timeout_flag type)
{
	struct drbd2_req *req = drbd2_req(ctx);

	if (nla_put_u32(req->reply_skb, DRBD2_A_TIMEOUT_TYPE, type)) {
		nlmsg_free(req->reply_skb);
		req->reply_skb = NULL;
		return -EMSGSIZE;
	}
	req->payload_reply = true;
	return NO_ERROR;
}

/*
 * The generated entry points. Each runs the wire-format independent
 * command implementation in drbd_nl.c and turns an ERR_* outcome into the
 * errno and extended ACK this dialect reports errors with.
 */
static int drbd2_do(struct genl_info *info, int (*fn)(struct drbd_adm_ctx *ctx))
{
	struct drbd_adm_ctx *ctx = info->user_ptr[0];
	struct drbd2_req *req = drbd2_req(ctx);
	int err;

	err = fn(ctx);
	if (!err) {
		if (drbd2_is_ret_code(ctx->result))
			err = drbd2_errno(ctx->result);
		else if (ctx->result < SS_AFTER_LAST_ERROR)
			err = ctx->result;	/* a plain -errno */
	}
	if (err) {
		drbd2_set_extack(info, ctx);
		nlmsg_free(req->reply_skb);
		req->reply_skb = NULL;
	}
	return err;
}

#define DRBD2_DOIT(cmd, fn)						\
int drbd2_nl_##cmd##_doit(struct sk_buff *skb, struct genl_info *info)	\
{									\
	return drbd2_do(info, fn);					\
}

DRBD2_DOIT(resource_new, drbd_adm_new_resource)
DRBD2_DOIT(resource_del, drbd_adm_del_resource)
DRBD2_DOIT(resource_set, drbd_adm_resource_opts)
DRBD2_DOIT(resource_rename, drbd_adm_rename_resource)
DRBD2_DOIT(resource_down, drbd_adm_down)
DRBD2_DOIT(resource_primary, drbd_adm_primary)
DRBD2_DOIT(resource_secondary, drbd_adm_secondary)
DRBD2_DOIT(resource_suspend_io, drbd_adm_suspend_io)
DRBD2_DOIT(resource_resume_io, drbd_adm_resume_io)
DRBD2_DOIT(device_new, drbd_adm_new_minor)
DRBD2_DOIT(device_del, drbd_adm_del_minor)
DRBD2_DOIT(device_attach, drbd_adm_attach)
DRBD2_DOIT(device_detach, drbd_adm_detach)
DRBD2_DOIT(disk_set, drbd_adm_disk_opts)
DRBD2_DOIT(device_resize, drbd_adm_resize)
DRBD2_DOIT(device_outdate, drbd_adm_outdate)
DRBD2_DOIT(device_invalidate, drbd_adm_invalidate)
DRBD2_DOIT(device_new_current_uuid, drbd_adm_new_c_uuid)
DRBD2_DOIT(connection_new, drbd_adm_new_peer)
DRBD2_DOIT(connection_del, drbd_adm_del_peer)
DRBD2_DOIT(connection_connect, drbd_adm_connect)
DRBD2_DOIT(connection_disconnect, drbd_adm_disconnect)
DRBD2_DOIT(connection_set, drbd_adm_net_opts)
DRBD2_DOIT(connection_forget, drbd_adm_forget_peer)
DRBD2_DOIT(path_new, drbd_adm_new_path)
DRBD2_DOIT(path_del, drbd_adm_del_path)
DRBD2_DOIT(peer_device_set, drbd_adm_peer_device_opts)
DRBD2_DOIT(peer_device_invalidate, drbd_adm_invalidate_peer)
DRBD2_DOIT(peer_device_pause_sync, drbd_adm_pause_sync)
DRBD2_DOIT(peer_device_resume_sync, drbd_adm_resume_sync)
DRBD2_DOIT(peer_device_start_ov, drbd_adm_start_ov)
DRBD2_DOIT(timeout_type_get, drbd_adm_get_timeout_type)

/*
 * Dumps.
 *
 * The core walks the objects; everything below turns one object into one
 * message of this dialect. This dialect has no room for a result code in
 * a dump message, so a "retcode" other than NO_ERROR aborts the dump with
 * the matching errno instead.
 */

static void *drbd2_dump_put(struct sk_buff *skb, struct netlink_callback *cb, u8 cmd)
{
	return genlmsg_put(skb, NETLINK_CB(cb->skb).portid, cb->nlh->nlmsg_seq,
			   &drbd2_nl_family, NLM_F_MULTI, cmd);
}

static int drbd2_emit_resource(struct sk_buff *skb, struct netlink_callback *cb,
			       struct drbd_resource *resource,
			       struct resource_info *info,
			       struct resource_statistics *statistics)
{
	void *dh = drbd2_dump_put(skb, cb, DRBD2_CMD_RESOURCE_GET);

	if (!dh)
		return -EMSGSIZE;
	if (drbd2_put_resource(skb, DRBD2_A_RESOURCE, resource, &resource->res_opts,
			       info, statistics, NULL)) {
		genlmsg_cancel(skb, dh);
		return -EMSGSIZE;
	}
	genlmsg_end(skb, dh);
	return 0;
}

static int drbd2_emit_device(struct sk_buff *skb, struct netlink_callback *cb, int retcode,
			     struct drbd_device *device, struct disk_conf *disk_conf,
			     struct device_info *info,
			     struct device_statistics *statistics)
{
	void *dh;

	if (retcode != NO_ERROR)
		return drbd2_errno(retcode);
	dh = drbd2_dump_put(skb, cb, DRBD2_CMD_DEVICE_GET);
	if (!dh)
		return -EMSGSIZE;
	if (drbd2_put_device(skb, DRBD2_A_DEVICE, device, disk_conf,
			     &device->device_conf, info, statistics)) {
		genlmsg_cancel(skb, dh);
		return -EMSGSIZE;
	}
	genlmsg_end(skb, dh);
	return 0;
}

static int drbd2_emit_connection(struct sk_buff *skb, struct netlink_callback *cb, int retcode,
				 struct drbd_resource *resource,
				 struct drbd_connection *connection,
				 struct net_conf *net_conf,
				 struct connection_info *info,
				 struct connection_statistics *statistics)
{
	void *dh;

	if (retcode != NO_ERROR)
		return drbd2_errno(retcode);
	dh = drbd2_dump_put(skb, cb, DRBD2_CMD_CONNECTION_GET);
	if (!dh)
		return -EMSGSIZE;
	if (drbd2_put_connection(skb, DRBD2_A_CONNECTION, resource, connection,
				 net_conf, info, statistics)) {
		genlmsg_cancel(skb, dh);
		return -EMSGSIZE;
	}
	genlmsg_end(skb, dh);
	return 0;
}

static int drbd2_emit_peer_device(struct sk_buff *skb, struct netlink_callback *cb, int retcode,
				  struct drbd_peer_device *peer_device, unsigned int minor,
				  struct peer_device_info *info,
				  struct peer_device_statistics *statistics,
				  struct peer_device_conf *conf)
{
	void *dh;

	if (retcode != NO_ERROR)
		return drbd2_errno(retcode);
	dh = drbd2_dump_put(skb, cb, DRBD2_CMD_PEER_DEVICE_GET);
	if (!dh)
		return -EMSGSIZE;
	if (drbd2_put_peer_device(skb, DRBD2_A_PEER_DEVICE, peer_device, conf,
				  info, statistics)) {
		genlmsg_cancel(skb, dh);
		return -EMSGSIZE;
	}
	genlmsg_end(skb, dh);
	return 0;
}

static int drbd2_emit_path(struct sk_buff *skb, struct netlink_callback *cb, int retcode,
			   struct drbd_resource *resource, struct drbd_connection *connection,
			   struct drbd_path *path, struct drbd_path_info *info)
{
	void *dh;

	if (retcode != NO_ERROR)
		return drbd2_errno(retcode);
	dh = drbd2_dump_put(skb, cb, DRBD2_CMD_PATH_GET);
	if (!dh)
		return -EMSGSIZE;
	if (drbd2_put_path(skb, DRBD2_A_PATH, resource, connection, path, info)) {
		genlmsg_cancel(skb, dh);
		return -EMSGSIZE;
	}
	genlmsg_end(skb, dh);
	return 0;
}

/*
 * The dump callbacks run outside the genl lock and get the request as a
 * raw message, so the optional context nest is looked up by hand.
 */
static struct nlattr *drbd2_find_context_attr(const struct nlmsghdr *nlh, int attr)
{
	struct nlattr *nla;

	nla = nla_find(nlmsg_attrdata(nlh, GENL_HDRLEN),
		       nlmsg_attrlen(nlh, GENL_HDRLEN), DRBD2_A_CONTEXT);
	if (!nla)
		return NULL;
	return nla_find_nested(nla, attr);
}

/*
 * Resolve the optional resource-name filter of a dump on its first call.
 * The core expects the resource in cb->args[0], with a reference that the
 * matching _done callback drops again. Returns -ENOENT when the name does
 * not name a resource, and 0 when there is nothing to filter by.
 */
static int drbd2_dump_filter(struct netlink_callback *cb, int holder_nr)
{
	struct drbd_resource *resource;
	struct nlattr *filter;

	filter = drbd2_find_context_attr(cb->nlh, DRBD2_A_CONTEXT_RESOURCE_NAME);
	if (IS_ERR_OR_NULL(filter))
		return 0;
	resource = drbd_find_resource(nla_data(filter));
	if (!resource)
		return -ENOENT;
	kref_debug_get(&resource->kref_debug, holder_nr);
	cb->args[0] = (long)resource;
	return 0;
}

int drbd2_nl_resource_get_dumpit(struct sk_buff *skb, struct netlink_callback *cb)
{
	return drbd_dump_resources(skb, cb, &drbd2_dialect);
}

int drbd2_nl_device_get_done(struct netlink_callback *cb)
{
	return drbd_dump_devices_done(cb);
}

int drbd2_nl_device_get_dumpit(struct sk_buff *skb, struct netlink_callback *cb)
{
	if (!cb->args[0] && !cb->args[1]) {
		int err = drbd2_dump_filter(cb, 7);

		if (err)
			return err;
	}
	return drbd_dump_devices(skb, cb, &drbd2_dialect);
}

int drbd2_nl_connection_get_done(struct netlink_callback *cb)
{
	return drbd_dump_connections_done(cb);
}

int drbd2_nl_connection_get_dumpit(struct sk_buff *skb, struct netlink_callback *cb)
{
	if (!cb->args[0]) {
		int err = drbd2_dump_filter(cb, 6);

		if (err)
			return err;
		if (cb->args[0])
			cb->args[1] = DRBD_DUMP_SINGLE_RESOURCE;
	}
	return drbd_dump_connections(skb, cb, &drbd2_dialect);
}

int drbd2_nl_peer_device_get_done(struct netlink_callback *cb)
{
	return drbd_dump_peer_devices_done(cb);
}

int drbd2_nl_peer_device_get_dumpit(struct sk_buff *skb, struct netlink_callback *cb)
{
	if (!cb->args[0] && !cb->args[1]) {
		int err = drbd2_dump_filter(cb, 9);

		if (err)
			return err;
	}
	return drbd_dump_peer_devices(skb, cb, &drbd2_dialect);
}

int drbd2_nl_path_get_done(struct netlink_callback *cb)
{
	return drbd_dump_paths_done(cb);
}

int drbd2_nl_path_get_dumpit(struct sk_buff *skb, struct netlink_callback *cb)
{
	if (!cb->args[0]) {
		int err = drbd2_dump_filter(cb, 10);

		if (err)
			return err;
		if (cb->args[0])
			cb->args[1] = DRBD_DUMP_SINGLE_RESOURCE;
	}
	return drbd_dump_paths(skb, cb, &drbd2_dialect);
}

int drbd2_nl_state_get_done(struct netlink_callback *cb)
{
	return drbd_dump_initial_state_done(cb);
}

int drbd2_nl_state_get_dumpit(struct sk_buff *skb, struct netlink_callback *cb)
{
	/* the replayed state changes are sent under the sequence number of the dump */
	return drbd_dump_initial_state(skb, cb, &drbd2_dialect, cb->nlh->nlmsg_seq);
}

/*
 * Notifications.
 *
 * With an skb this is the initial state snapshot of the state-get dump:
 * append the message to that skb. Without one, allocate a message and
 * multicast it to the "events" group. Both carry the same attributes; the
 * command tells them apart. The sequence number comes from the core; it
 * is the same for every dialect describing the event.
 */

static u32 drbd2_state_change_action(enum drbd_notification_type type)
{
	switch (type & ~NOTIFY_FLAGS) {
	case NOTIFY_CREATE:	return DRBD2_STATE_CHANGE_ACTION_CREATE;
	case NOTIFY_CHANGE:	return DRBD2_STATE_CHANGE_ACTION_CHANGE;
	case NOTIFY_DESTROY:	return DRBD2_STATE_CHANGE_ACTION_DESTROY;
	case NOTIFY_RENAME:	return DRBD2_STATE_CHANGE_ACTION_RENAME;
	default:		return DRBD2_STATE_CHANGE_ACTION_EXISTS;
	}
}

static void *drbd2_state_change_put(struct sk_buff *skb, unsigned int seq, bool replay,
				    enum drbd_notification_type type)
{
	void *dh = genlmsg_put(skb, 0, seq, &drbd2_nl_family,
			       replay ? NLM_F_MULTI : 0,
			       replay ? DRBD2_CMD_STATE_GET : DRBD2_CMD_STATE_CHANGE_NTF);

	if (!dh)
		return NULL;
	if (nla_put_u32(skb, DRBD2_A_STATE_CHANGE_ACTION,
			drbd2_state_change_action(type)))
		goto fail;
	if ((type & NOTIFY_CONTINUES) &&
	    nla_put_flag(skb, DRBD2_A_STATE_CHANGE_MORE))
		goto fail;
	return dh;

fail:
	genlmsg_cancel(skb, dh);
	return NULL;
}

static int drbd2_notify_resource_state(struct sk_buff *skb, unsigned int seq,
				       struct drbd_resource *resource,
				       struct resource_info *info,
				       struct rename_resource_info *rename_info,
				       enum drbd_notification_type type)
{
	struct resource_statistics statistics;
	bool multicast = !skb;
	void *dh;
	int err;

	if (multicast) {
		skb = genlmsg_new(NLMSG_GOODSIZE, GFP_NOIO);
		err = -ENOMEM;
		if (!skb)
			goto failed;
	}

	err = -EMSGSIZE;
	dh = drbd2_state_change_put(skb, seq, !multicast, type);
	if (!dh)
		goto nla_put_failure;
	resource_to_statistics(&statistics, resource);
	if (drbd2_put_resource(skb, DRBD2_A_STATE_CHANGE_RESOURCE, resource, NULL,
			       info, &statistics, rename_info))
		goto nla_put_failure;
	genlmsg_end(skb, dh);
	if (multicast) {
		err = drbd2_genl_multicast_events(skb);
		/* skb has been consumed or freed in netlink_broadcast() */
		if (err && err != -ESRCH)
			goto failed;
	}
	return 0;

nla_put_failure:
	nlmsg_free(skb);
failed:
	drbd_err(resource, "Error %d while broadcasting event. Event seq:%u\n", err, seq);
	return err;
}

static int drbd2_notify_device_state(struct sk_buff *skb, unsigned int seq,
				     struct drbd_device *device,
				     struct device_info *info,
				     enum drbd_notification_type type)
{
	struct device_statistics statistics;
	bool multicast = !skb;
	void *dh;
	int err;

	if (multicast) {
		skb = genlmsg_new(NLMSG_GOODSIZE, GFP_NOIO);
		err = -ENOMEM;
		if (!skb)
			goto failed;
	}

	err = -EMSGSIZE;
	dh = drbd2_state_change_put(skb, seq, !multicast, type);
	if (!dh)
		goto nla_put_failure;
	device_to_statistics(&statistics, device);
	if (drbd2_put_device(skb, DRBD2_A_STATE_CHANGE_DEVICE, device, NULL, NULL,
			     (type & ~NOTIFY_FLAGS) == NOTIFY_DESTROY ? NULL : info,
			     &statistics))
		goto nla_put_failure;
	genlmsg_end(skb, dh);
	if (multicast) {
		err = drbd2_genl_multicast_events(skb);
		/* skb has been consumed or freed in netlink_broadcast() */
		if (err && err != -ESRCH)
			goto failed;
	}
	return 0;

nla_put_failure:
	nlmsg_free(skb);
failed:
	drbd_err(device, "Error %d while broadcasting event. Event seq:%u\n", err, seq);
	return err;
}

static int drbd2_notify_connection_state(struct sk_buff *skb, unsigned int seq,
					 struct drbd_connection *connection,
					 struct connection_info *info,
					 enum drbd_notification_type type)
{
	struct connection_statistics statistics;
	bool multicast = !skb;
	void *dh;
	int err;

	if (multicast) {
		skb = genlmsg_new(NLMSG_GOODSIZE, GFP_NOIO);
		err = -ENOMEM;
		if (!skb)
			goto failed;
	}

	err = -EMSGSIZE;
	dh = drbd2_state_change_put(skb, seq, !multicast, type);
	if (!dh)
		goto nla_put_failure;
	connection_to_statistics(&statistics, connection);
	if (drbd2_put_connection(skb, DRBD2_A_STATE_CHANGE_CONNECTION,
				 connection->resource, connection, NULL,
				 (type & ~NOTIFY_FLAGS) == NOTIFY_DESTROY ? NULL : info,
				 &statistics))
		goto nla_put_failure;
	genlmsg_end(skb, dh);
	if (multicast) {
		err = drbd2_genl_multicast_events(skb);
		/* skb has been consumed or freed in netlink_broadcast() */
		if (err && err != -ESRCH)
			goto failed;
	}
	return 0;

nla_put_failure:
	nlmsg_free(skb);
failed:
	drbd_err(connection, "Error %d while broadcasting event. Event seq:%u\n", err, seq);
	return err;
}

static int drbd2_notify_peer_device_state(struct sk_buff *skb, unsigned int seq,
					  struct drbd_peer_device *peer_device,
					  struct peer_device_info *info,
					  enum drbd_notification_type type)
{
	struct peer_device_statistics statistics;
	bool multicast = !skb;
	void *dh;
	int err;

	if (multicast) {
		skb = genlmsg_new(NLMSG_GOODSIZE, GFP_NOIO);
		err = -ENOMEM;
		if (!skb)
			goto failed;
	}

	err = -EMSGSIZE;
	dh = drbd2_state_change_put(skb, seq, !multicast, type);
	if (!dh)
		goto nla_put_failure;
	peer_device_to_statistics(&statistics, peer_device);
	if (drbd2_put_peer_device(skb, DRBD2_A_STATE_CHANGE_PEER_DEVICE, peer_device, NULL,
				  (type & ~NOTIFY_FLAGS) == NOTIFY_DESTROY ? NULL : info,
				  &statistics))
		goto nla_put_failure;
	genlmsg_end(skb, dh);
	if (multicast) {
		err = drbd2_genl_multicast_events(skb);
		/* skb has been consumed or freed in netlink_broadcast() */
		if (err && err != -ESRCH)
			goto failed;
	}
	return 0;

nla_put_failure:
	nlmsg_free(skb);
failed:
	drbd_err(peer_device, "Error %d while broadcasting event. Event seq:%u\n", err, seq);
	return err;
}

static int drbd2_notify_path_state(struct sk_buff *skb, unsigned int seq,
				   /* until we have a backpointer in drbd_path,
				    * we need an explicit connection:
				    */
				   struct drbd_connection *connection,
				   struct drbd_path *path,
				   struct drbd_path_info *info,
				   enum drbd_notification_type type)
{
	bool multicast = !skb;
	void *dh;
	int err;

	if (multicast) {
		skb = genlmsg_new(NLMSG_GOODSIZE, GFP_NOIO);
		err = -ENOMEM;
		if (!skb)
			goto failed;
	}

	err = -EMSGSIZE;
	dh = drbd2_state_change_put(skb, seq, !multicast, type);
	if (!dh)
		goto nla_put_failure;
	if (drbd2_put_path(skb, DRBD2_A_STATE_CHANGE_PATH, connection->resource,
			   connection, path, info))
		goto nla_put_failure;
	genlmsg_end(skb, dh);
	if (multicast) {
		err = drbd2_genl_multicast_events(skb);
		/* skb has been consumed or freed in netlink_broadcast() */
		if (err && err != -ESRCH)
			goto failed;
	}
	return 0;

nla_put_failure:
	nlmsg_free(skb);
failed:
	/* FIXME add path specifics to our drbd_polymorph_printk.h */
	drbd_err(connection, "path: Error %d while broadcasting event. Event seq:%u\n",
		 err, seq);
	return err;
}

/* Helper events are never replayed, so "skb" is always NULL here. */
static int drbd2_notify_helper(struct sk_buff *skb, unsigned int seq,
			       struct drbd_device *device, struct drbd_connection *connection,
			       const char *name, int status,
			       enum drbd_notification_type type)
{
	struct drbd_resource *resource = device ? device->resource : connection->resource;
	struct nlattr *nla;
	void *dh;
	int err;

	skb = genlmsg_new(NLMSG_GOODSIZE, GFP_NOIO);
	err = -ENOMEM;
	if (!skb)
		goto fail;

	err = -EMSGSIZE;
	dh = genlmsg_put(skb, 0, seq, &drbd2_nl_family, 0, DRBD2_CMD_HELPER_NTF);
	if (!dh)
		goto fail;
	if (drbd2_put_context(skb, DRBD2_A_CONTEXT, resource, connection, device, NULL))
		goto fail;
	nla = nla_nest_start(skb, DRBD2_A_HELPER);
	if (!nla)
		goto fail;
	if (nla_put_string(skb, DRBD2_A_HELPER_INFO_NAME, name) ||
	    nla_put_u32(skb, DRBD2_A_HELPER_INFO_STATUS, status) ||
	    nla_put_u32(skb, DRBD2_A_HELPER_INFO_PHASE,
			(type & ~NOTIFY_FLAGS) == NOTIFY_RESPONSE ?
			DRBD2_HELPER_PHASE_RESPONSE : DRBD2_HELPER_PHASE_CALL))
		goto fail;
	nla_nest_end(skb, nla);
	genlmsg_end(skb, dh);
	err = drbd2_genl_multicast_events(skb);
	skb = NULL;
	/* skb has been consumed or freed in netlink_broadcast() */
	if (err && err != -ESRCH)
		goto fail;
	return 0;

fail:
	nlmsg_free(skb);
	drbd_err(resource, "Error %d while broadcasting event. Event seq:%u\n", err, seq);
	return err;
}

/*
 * The end of the state-get dump needs no message of its own: appending
 * nothing ends the dump, and netlink terminates it with NLMSG_DONE.
 */
static int drbd2_notify_initial_state_done(struct sk_buff *skb, unsigned int seq)
{
	return 0;
}

static const struct drbd_nl_dialect drbd2_dialect = {
	.name = "drbd2",
	.has_set = drbd2_has_set,
	.overlay = drbd2_overlay,
	.attr_present = drbd2_attr_present,
	.put_timeout_type = drbd2_put_timeout_type,
	.emit_resource = drbd2_emit_resource,
	.emit_device = drbd2_emit_device,
	.emit_connection = drbd2_emit_connection,
	.emit_peer_device = drbd2_emit_peer_device,
	.emit_path = drbd2_emit_path,
	.notify_resource_state = drbd2_notify_resource_state,
	.notify_device_state = drbd2_notify_device_state,
	.notify_connection_state = drbd2_notify_connection_state,
	.notify_peer_device_state = drbd2_notify_peer_device_state,
	.notify_path_state = drbd2_notify_path_state,
	.notify_helper = drbd2_notify_helper,
	.notify_initial_state_done = drbd2_notify_initial_state_done,
};

int drbd_nl_drbd2_init(void)
{
	int err = genl_register_family(&drbd2_nl_family);

	if (err)
		return err;
	err = drbd_nl_register_dialect(&drbd2_dialect);
	if (err)
		genl_unregister_family(&drbd2_nl_family);
	return err;
}

void drbd_nl_drbd2_exit(void)
{
	genl_unregister_family(&drbd2_nl_family);
}
