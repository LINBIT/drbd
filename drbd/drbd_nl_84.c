// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026, LINBIT HA-Solutions GmbH.
 */

/*
 * The "drbd" generic netlink family at version 1: the dialect spoken by
 * DRBD 8.4 userland (drbd-utils 8.9.x). Everything here knows about the
 * bytes on the wire; the command implementations live in drbd_nl.c and
 * only ever see a struct drbd_adm_ctx.
 *
 * Needs CONFIG_DRBD_COMPAT_84 for the 8.4 metadata and /proc/drbd support
 * the dialect translates to.
 */

#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt

#include <linux/slab.h>
#include <linux/drbd.h>
#include <linux/drbd_limits.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/crc32c.h>
#include <net/genetlink.h>
#include <net/sock.h>

#include "drbd_int.h"
#include "drbd_nl.h"
#include "drbd_legacy_84.h"
#include "drbd-84/drbd_nl_gen.h"

static const struct drbd_nl_dialect drbd_nl_84_dialect;

/* Per-request state of the v1 dialect; hangs off drbd_adm_ctx.req. */
struct compat84_req {
	struct genl_info *info;
	struct sk_buff *reply_skb;
	struct drbd_genlmsghdr *reply_dh;

	/*
	 * Attributes that arrive inside one v1 container but belong to a
	 * different DRBD 9 struct than that container's overlay() dst.
	 * compat84_overlay() stashes them here; the handler that owns the
	 * real struct applies them. Each field carries its own "has_*"
	 * flag, set only when that attribute itself was present: the
	 * fields are independently optional on the wire, so a
	 * container-level flag would misreport unsent siblings as zero.
	 */

	/* the v1 disk_conf's resync-tuning fields -> struct drbd_peer_device_conf.
	 * Applied by compat84_apply_disk_conf_stash() if a peer device
	 * exists, else deferred to device->pending_peer_device_conf_84
	 * for the connect handler.
	 */
	struct {
		bool has_resync_rate;
		u32 resync_rate;
		bool has_c_plan_ahead;
		u32 c_plan_ahead;
		bool has_c_delay_target;
		u32 c_delay_target;
		bool has_c_fill_target;
		u32 c_fill_target;
		bool has_c_max_rate;
		u32 c_max_rate;
		bool has_c_min_rate;
		u32 c_min_rate;
	} peer_device_conf_84;

	/* v1 disk_conf.fencing -> drbd_net_conf.fencing_policy. Applied if a
	 * connection exists, else deferred to
	 * resource->pending_fencing_policy_84 for the connect handler.
	 */
	bool has_fencing_policy_84;
	u32 fencing_policy_84;

	/* v1 net_conf.{discard_my_data, tentative} -> struct drbd_connect_parms,
	 * applied through the DRBD_NL_SET_CONNECT_PARMS overlay case.
	 */
	struct {
		bool has_discard_my_data;
		unsigned char discard_my_data;
		bool has_tentative;
		unsigned char tentative;
	} connect_parms_84;

	/*
	 * ctx_my_addr/ctx_peer_addr from DRBD_NLA_CFG_CONTEXT, raw
	 * sockaddr bytes; v1 has no NLA_PATH_PARMS container. Parsed once
	 * in drbd_pre_doit(), read by the DRBD_NL_SET_PATH_PARMS overlay
	 * case and by compat84_resolve_peer_node_id(). *_len is 0 when the
	 * attribute was not sent.
	 */
	u8 ctx_my_addr[128];
	u32 ctx_my_addr_len;
	u8 ctx_peer_addr[128];
	u32 ctx_peer_addr_len;
};

/* One allocation for both, so that pre_doit zeroes the context only once. */
struct compat84_ctx {
	struct drbd_adm_ctx ctx;
	struct compat84_req req;
};

static inline struct compat84_req *compat84_req(struct drbd_adm_ctx *ctx)
{
	return ctx->req;
}

static const struct genl_multicast_group drbd_nl_mcgrps[] = {
	[DRBD_NLGRP_EVENTS] = { .name = "events", },
};

static struct genl_family drbd_nl_family __ro_after_init = {
	.name		= DRBD_FAMILY_NAME,
	.version	= DRBD_FAMILY_VERSION,
	.hdrsize	= NLA_ALIGN(sizeof(struct drbd_genlmsghdr)),
	.split_ops	= drbd_nl_ops,
	.n_split_ops	= ARRAY_SIZE(drbd_nl_ops),
	/*
	 * Every v1 command predates the reserved-field/flags checks that
	 * genl applies from resv_start_op onward; matches mainline's
	 * drbd_nl_family.
	 */
	.resv_start_op	= DRBD_ADM_INITIAL_STATE_DONE + 1,
	.mcgrps		= drbd_nl_mcgrps,
	.n_mcgrps	= ARRAY_SIZE(drbd_nl_mcgrps),
	.module		= THIS_MODULE,
	/* Register in every network namespace, like the v2 family. */
	.netnsok	= true,
};

static void drbd_adm_send_reply(struct sk_buff *skb, struct genl_info *info)
{
	genlmsg_end(skb, genlmsg_data(nlmsg_data(nlmsg_hdr(skb))));
	if (genlmsg_reply(skb, info))
		pr_err("error sending genl reply\n");
}

/* Used on a fresh reply_skb, this cannot fail: The only reason it could
 * fail was no space in skb, and there are 4k available.
 */
static int drbd_msg_put_info(struct sk_buff *skb, const char *info)
{
	struct nlattr *nla;
	int err = -EMSGSIZE;

	if (!info || !info[0])
		return 0;

	nla = nla_nest_start_noflag(skb, DRBD_NLA_CFG_REPLY);
	if (!nla)
		return err;

	err = nla_put_string(skb, DRBD_A_DRBD_CFG_REPLY_INFO_TEXT, info);
	if (err) {
		nla_nest_cancel(skb, nla);
		return err;
	}
	nla_nest_end(skb, nla);
	return 0;
}

/*
 * Serialize ctx->result and ctx->msg[] into the v1 reply. Only enum
 * drbd_state_rv values need remapping for the v1 wire; drbd_state_rv_84()
 * passes everything else through unchanged.
 */
static void compat84_put_outcome(struct drbd_adm_ctx *ctx)
{
	struct compat84_req *req = compat84_req(ctx);
	const char *p, *end;

	req->reply_dh->ret_code = drbd_state_rv_84(ctx->result);
	for (p = ctx->msg, end = ctx->msg + ctx->msg_len; p < end; p += strlen(p) + 1)
		drbd_msg_put_info(req->reply_skb, p);
}

static bool compat84_need_sys_admin(u8 cmd)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(drbd_nl_ops); i++)
		if (drbd_nl_ops[i].cmd == cmd)
			return 0 != (drbd_nl_ops[i].flags & GENL_ADMIN_PERM);
	return true;
}

/* The v1 command set: a subset of v2's, with a few commands renamed
 * (CHG_DISK_OPTS/CHG_NET_OPTS/INVAL_PEER) and none of the DRBD 9 only
 * commands (peers, paths, rename, forget-peer).
 */
static const unsigned int drbd_genl_cmd_flags_84[] = {
	[DRBD_ADM_NEW_MINOR]       = DRBD_ADM_NEED_RESOURCE,
	[DRBD_ADM_DEL_MINOR]       = DRBD_ADM_NEED_MINOR,
	[DRBD_ADM_NEW_RESOURCE]    = 0,
	[DRBD_ADM_DEL_RESOURCE]    = DRBD_ADM_NEED_RESOURCE,
	[DRBD_ADM_RESOURCE_OPTS]   = DRBD_ADM_NEED_RESOURCE,
	/*
	 * The command that creates a connection cannot require one to
	 * exist; the connect handler derives the peer node id from the
	 * address pair itself.
	 */
	[DRBD_ADM_CONNECT]         = DRBD_ADM_NEED_RESOURCE,
	[DRBD_ADM_DISCONNECT]      = DRBD_ADM_NEED_CONNECTION,
	[DRBD_ADM_ATTACH]          = DRBD_ADM_NEED_MINOR,
	[DRBD_ADM_RESIZE]          = DRBD_ADM_NEED_MINOR,
	/*
	 * v1 addresses primary/secondary by minor only (CTX_MINOR), unlike
	 * v2, which sends a resource name. drbd_adm_ctx_resolve() derives
	 * the resource from the device, which is all drbd_adm_set_role()
	 * needs.
	 */
	[DRBD_ADM_PRIMARY]         = DRBD_ADM_NEED_MINOR,
	[DRBD_ADM_SECONDARY]       = DRBD_ADM_NEED_MINOR,
	[DRBD_ADM_NEW_C_UUID]      = DRBD_ADM_NEED_MINOR,
	[DRBD_ADM_START_OV]        = DRBD_ADM_NEED_PEER_DEVICE,
	[DRBD_ADM_DETACH]          = DRBD_ADM_NEED_MINOR,
	[DRBD_ADM_INVALIDATE]      = DRBD_ADM_NEED_MINOR,
	[DRBD_ADM_INVAL_PEER]      = DRBD_ADM_NEED_PEER_DEVICE,
	[DRBD_ADM_PAUSE_SYNC]      = DRBD_ADM_NEED_PEER_DEVICE,
	[DRBD_ADM_RESUME_SYNC]     = DRBD_ADM_NEED_PEER_DEVICE,
	[DRBD_ADM_SUSPEND_IO]      = DRBD_ADM_NEED_MINOR,
	[DRBD_ADM_RESUME_IO]       = DRBD_ADM_NEED_MINOR,
	[DRBD_ADM_OUTDATE]         = DRBD_ADM_NEED_MINOR,
	[DRBD_ADM_GET_TIMEOUT_TYPE] = DRBD_ADM_NEED_PEER_DEVICE,
	[DRBD_ADM_DOWN]            = DRBD_ADM_NEED_RESOURCE | DRBD_ADM_IGNORE_VERSION,
	[DRBD_ADM_CHG_DISK_OPTS]   = DRBD_ADM_NEED_MINOR,
	[DRBD_ADM_CHG_NET_OPTS]    = DRBD_ADM_NEED_CONNECTION,
	[DRBD_ADM_GET_RESOURCES]   = 0,
	[DRBD_ADM_GET_DEVICES]     = 0,
	[DRBD_ADM_GET_CONNECTIONS] = 0,
	[DRBD_ADM_GET_PEER_DEVICES] = 0,
	[DRBD_ADM_GET_INITIAL_STATE] = 0,
};

/*
 * Highest nested attribute type the kernel knows for each top-level
 * attribute, for compat84_check_mandatory(). Kept apart from the netlink
 * policies: kernels before v4.20 take .len of an NLA_NESTED entry as a
 * minimum payload length, so the policies cannot carry it.
 */
static const u16 drbd_tla_nested_max_84[__DRBD_NLA_MAX] = {
	[DRBD_NLA_CFG_REPLY]			= DRBD_A_DRBD_CFG_REPLY_MAX,
	[DRBD_NLA_CFG_CONTEXT]			= DRBD_A_DRBD_CFG_CONTEXT_MAX,
	[DRBD_NLA_DISK_CONF]			= DRBD_A_DISK_CONF_MAX,
	[DRBD_NLA_RESOURCE_OPTS]		= DRBD_A_RES_OPTS_MAX,
	[DRBD_NLA_NET_CONF]			= DRBD_A_NET_CONF_MAX,
	[DRBD_NLA_SET_ROLE_PARMS]		= DRBD_A_SET_ROLE_PARMS_MAX,
	[DRBD_NLA_RESIZE_PARMS]			= DRBD_A_RESIZE_PARMS_MAX,
	[DRBD_NLA_STATE_INFO]			= DRBD_A_STATE_INFO_MAX,
	[DRBD_NLA_START_OV_PARMS]		= DRBD_A_START_OV_PARMS_MAX,
	[DRBD_NLA_NEW_C_UUID_PARMS]		= DRBD_A_NEW_C_UUID_PARMS_MAX,
	[DRBD_NLA_TIMEOUT_PARMS]		= DRBD_A_TIMEOUT_PARMS_MAX,
	[DRBD_NLA_DISCONNECT_PARMS]		= DRBD_A_DISCONNECT_PARMS_MAX,
	[DRBD_NLA_DETACH_PARMS]			= DRBD_A_DETACH_PARMS_MAX,
	[DRBD_NLA_RESOURCE_INFO]		= DRBD_A_RESOURCE_INFO_MAX,
	[DRBD_NLA_DEVICE_INFO]			= DRBD_A_DEVICE_INFO_MAX,
	[DRBD_NLA_CONNECTION_INFO]		= DRBD_A_CONNECTION_INFO_MAX,
	[DRBD_NLA_PEER_DEVICE_INFO]		= DRBD_A_PEER_DEVICE_INFO_MAX,
	[DRBD_NLA_RESOURCE_STATISTICS]		= DRBD_A_RESOURCE_STATISTICS_MAX,
	[DRBD_NLA_DEVICE_STATISTICS]		= DRBD_A_DEVICE_STATISTICS_MAX,
	[DRBD_NLA_CONNECTION_STATISTICS]	= DRBD_A_CONNECTION_STATISTICS_MAX,
	[DRBD_NLA_PEER_DEVICE_STATISTICS]	= DRBD_A_PEER_DEVICE_STATISTICS_MAX,
	[DRBD_NLA_NOTIFICATION_HEADER]		= DRBD_A_DRBD_NOTIFICATION_HEADER_MAX,
	[DRBD_NLA_HELPER]			= DRBD_A_DRBD_HELPER_INFO_MAX,
};

/* Strip DRBD_GENLA_F_MANDATORY from nested attrs before standard parsing.
 * Reject unknown attrs that had the mandatory bit set.
 */
static int compat84_check_mandatory(const struct genl_split_ops *ops,
				    struct genl_info *info)
{
	int i;

	for (i = 0; i <= ops->maxattr && i < ARRAY_SIZE(drbd_tla_nested_max_84); i++) {
		struct nlattr *tla = info->attrs[i];
		struct nlattr *nla;
		int rem;

		if (!tla || !drbd_tla_nested_max_84[i])
			continue;

		nla_for_each_nested(nla, tla, rem) {
			if (nla->nla_type & DRBD_GENLA_F_MANDATORY) {
				nla->nla_type &= ~DRBD_GENLA_F_MANDATORY;
				if (nla_type(nla) > drbd_tla_nested_max_84[i])
					return -EOPNOTSUPP;
			}
		}
	}
	return 0;
}

/*
 * v1 has no ctx_peer_node_id attribute: an 8.4 resource has at most one
 * peer. Resolve adm_ctx->peer_node_id (and adm_ctx->resource, when
 * nothing else identifies it) here, before drbd_adm_ctx_resolve() runs,
 * so that function needs no v1-specific fallback.
 *
 * Disconnect and net-options address the connection by its endpoint
 * addresses (CTX_CONNECTION) and carry neither a resource name nor a
 * minor, so the addresses are matched against every 8.4-mode resource's
 * connections. Connect never gets here: it needs only the resource name
 * and derives its own peer node id. The remaining peer-scoped commands
 * (start-ov, invalidate-remote, pause-sync, resume-sync,
 * get-timeout-type) address a minor only; an 8.4-mode resource has at
 * most one connection, and the minor also pins the volume.
 *
 * Only 8.4-mode resources are considered, so a v1 request cannot act on
 * a DRBD 9 native resource by naming its addresses. Both branches are
 * skipped when a resource name was sent as well: drbd_adm_ctx_resolve()
 * re-resolves adm_ctx->resource from the name unconditionally and
 * would leak the reference taken here.
 */
static void compat84_resolve_peer_node_id(struct drbd_adm_ctx *adm_ctx)
{
	struct compat84_req *req = compat84_req(adm_ctx);
	struct drbd_connection *connection = NULL;
	struct drbd_resource *resource = NULL;
	unsigned int volume = VOLUME_UNSPECIFIED;

	rcu_read_lock();
	if (req->ctx_my_addr_len && req->ctx_peer_addr_len && !adm_ctx->resource_name) {
		struct drbd_resource *r;

		for_each_resource_rcu(r, &drbd_resources) {
			struct drbd_connection *c;

			if (!r->res_opts.drbd8_compat_mode)
				continue;

			for_each_connection_rcu(c, r) {
				struct drbd_path *path;

				list_for_each_entry_rcu(path, &c->transport.paths, list) {
					if (path->my_addr_len != req->ctx_my_addr_len ||
					    memcmp(&path->my_addr, req->ctx_my_addr,
						   path->my_addr_len))
						continue;
					if (path->peer_addr_len != req->ctx_peer_addr_len ||
					    memcmp(&path->peer_addr, req->ctx_peer_addr,
						   path->peer_addr_len))
						continue;
					connection = c;
					break;
				}
				if (connection)
					break;
			}
			if (connection) {
				resource = r;
				break;
			}
		}
	} else if (adm_ctx->minor != -1U && !adm_ctx->resource_name) {
		struct drbd_device *device = minor_to_device(adm_ctx->minor);

		if (device && device->resource->res_opts.drbd8_compat_mode) {
			resource = device->resource;
			connection = list_first_or_null_rcu(&resource->connections,
							     struct drbd_connection,
							     connections);
			volume = device->vnr;
		}
	}

	if (connection) {
		kref_get(&resource->kref);
		kref_debug_get(&resource->kref_debug, 2);
		adm_ctx->resource = resource;
		adm_ctx->peer_node_id = connection->peer_node_id;
		if (volume != VOLUME_UNSPECIFIED)
			adm_ctx->volume = volume;
	}
	rcu_read_unlock();
}

/*
 * Every resource this dialect creates is in DRBD 8.4 compatibility mode.
 * A native DRBD 9 resource (from the drbd2 family) is not one 8.4
 * userland can drive, whether it is named by resource or by minor.
 */
static bool compat84_reject_native(struct drbd_adm_ctx *adm_ctx)
{
	if (!adm_ctx->resource || adm_ctx->resource->res_opts.drbd8_compat_mode)
		return false;

	drbd_adm_msg(adm_ctx, "%s", "not a DRBD 8.4 compatibility mode resource");
	adm_ctx->result = ERR_INVALID_REQUEST;
	return true;
}

/*
 * Allocates the command context together with the v1 request state,
 * stores it in info->user_ptr[0], prepares the reply skb and resolves the
 * objects the command refers to. Rejects unknown netlink versions with
 * -EINVAL.
 */
int drbd_pre_doit(const struct genl_split_ops *ops, struct sk_buff *skb,
		  struct genl_info *info)
{
	struct drbd_genlmsghdr *d_in = genl_info_userhdr(info);
	const u8 cmd = info->genlhdr->cmd;
	struct drbd_adm_ctx *adm_ctx;
	struct compat84_ctx *cctx;
	struct compat84_req *req;
	unsigned int flags;
	int err;

	err = compat84_check_mandatory(ops, info);
	if (err)
		return err;

	/* Look up per-command flags */
	flags = (cmd < ARRAY_SIZE(drbd_genl_cmd_flags_84)) ? drbd_genl_cmd_flags_84[cmd] : 0;

	if (info->genlhdr->version != DRBD_FAMILY_VERSION && !(flags & DRBD_ADM_IGNORE_VERSION))
		return -EINVAL;

	/*
	 * genl_rcv_msg() only checks if commands with the GENL_ADMIN_PERM flag
	 * set have CAP_NET_ADMIN; we also require CAP_SYS_ADMIN for
	 * administrative commands.
	 */
	if (compat84_need_sys_admin(cmd) && !capable(CAP_SYS_ADMIN))
		return -EPERM;

	cctx = kzalloc_obj(struct compat84_ctx);
	if (!cctx)
		return -ENOMEM;

	adm_ctx = &cctx->ctx;
	req = &cctx->req;
	adm_ctx->d = &drbd_nl_84_dialect;
	adm_ctx->req = req;
	req->info = info;

	adm_ctx->net = sock_net(skb->sk);

	req->reply_skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!req->reply_skb) {
		err = -ENOMEM;
		goto fail;
	}

	req->reply_dh = genlmsg_put_reply(req->reply_skb,
					info, &drbd_nl_family, 0, cmd);
	/* put of a few bytes into a fresh skb of >= 4k will always succeed.
	 * but anyways
	 */
	if (!req->reply_dh) {
		err = -ENOMEM;
		goto fail;
	}

	req->reply_dh->minor = d_in->minor;
	adm_ctx->minor = d_in->minor;
	adm_ctx->result = NO_ERROR;
	adm_ctx->set_defaults = !!(d_in->flags & DRBD_GENL_F_SET_DEFAULTS);

	adm_ctx->volume = VOLUME_UNSPECIFIED;
	adm_ctx->peer_node_id = PEER_NODE_ID_UNSPECIFIED;
	if (info->attrs[DRBD_NLA_CFG_CONTEXT]) {
		struct nlattr *nla;
		struct nlattr **nested_attr_tb;
		/* parse and validate only */
		err = drbd_cfg_context_ntb_from_attrs(&nested_attr_tb, info);
		if (err)
			goto fail;

		/* It was present, and valid,
		 * copy it over to the reply skb.
		 */
		err = nla_put_nohdr(req->reply_skb,
				info->attrs[DRBD_NLA_CFG_CONTEXT]->nla_len,
				info->attrs[DRBD_NLA_CFG_CONTEXT]);
		if (err) {
			kfree(nested_attr_tb);
			goto fail;
		}

		/* and assign stuff to the adm_ctx */
		nla = nested_attr_tb[DRBD_A_DRBD_CFG_CONTEXT_CTX_VOLUME];
		if (nla)
			adm_ctx->volume = nla_get_u32(nla);
		nla = nested_attr_tb[DRBD_A_DRBD_CFG_CONTEXT_CTX_RESOURCE_NAME];
		if (nla)
			adm_ctx->resource_name = nla_data(nla);
		/* No ctx_peer_node_id in v1; the addresses stand in for it. */
		nla = nested_attr_tb[DRBD_A_DRBD_CFG_CONTEXT_CTX_MY_ADDR];
		if (nla) {
			req->ctx_my_addr_len = min_t(u32, nla_len(nla), sizeof(req->ctx_my_addr));
			memcpy(req->ctx_my_addr, nla_data(nla), req->ctx_my_addr_len);
		}
		nla = nested_attr_tb[DRBD_A_DRBD_CFG_CONTEXT_CTX_PEER_ADDR];
		if (nla) {
			req->ctx_peer_addr_len =
				min_t(u32, nla_len(nla), sizeof(req->ctx_peer_addr));
			memcpy(req->ctx_peer_addr, nla_data(nla), req->ctx_peer_addr_len);
		}
		kfree(nested_attr_tb);
	}

	/*
	 * Only commands that need a connection or peer device inside
	 * drbd_adm_ctx_resolve(); connect is deliberately excluded.
	 */
	if (flags & (DRBD_ADM_NEED_CONNECTION | DRBD_ADM_NEED_PEER_DEVICE))
		compat84_resolve_peer_node_id(adm_ctx);

	if (drbd_adm_ctx_resolve(adm_ctx, flags) != NO_ERROR ||
	    compat84_reject_native(adm_ctx)) {
		/* Send error reply now; NULL reply_skb so the handler bails
		 * out. post_doit will drop the kref references.
		 */
		compat84_put_outcome(adm_ctx);
		drbd_adm_send_reply(req->reply_skb, info);
		req->reply_skb = NULL;
	}

	info->user_ptr[0] = adm_ctx;
	return 0;

fail:
	/* Fatal error while preparing the reply; nothing is resolved yet. */
	nlmsg_free(req->reply_skb);
	kfree(cctx);
	info->user_ptr[0] = NULL;
	return err;
}

/*
 * Sends the reply, drops the references acquired while resolving, and
 * frees the context.
 */
void drbd_post_doit(const struct genl_split_ops *ops, struct sk_buff *skb,
		    struct genl_info *info)
{
	struct drbd_adm_ctx *adm_ctx = info->user_ptr[0];
	struct compat84_req *req;

	if (!adm_ctx)
		return;

	req = compat84_req(adm_ctx);
	if (req->reply_skb) {
		compat84_put_outcome(adm_ctx);
		drbd_adm_send_reply(req->reply_skb, info);
	}

	drbd_adm_ctx_release(adm_ctx);
	kfree(container_of(adm_ctx, struct compat84_ctx, ctx));
}

static bool compat84_has_set(struct drbd_adm_ctx *ctx, enum drbd_nl_attr_set set)
{
	static const u16 tla[__DRBD_NL_SET_MAX] = {
		[DRBD_NL_SET_DISK_CONF]		= DRBD_NLA_DISK_CONF,
		[DRBD_NL_SET_NET_CONF]		= DRBD_NLA_NET_CONF,
		[DRBD_NL_SET_RES_OPTS]		= DRBD_NLA_RESOURCE_OPTS,
		[DRBD_NL_SET_SET_ROLE_PARMS]	= DRBD_NLA_SET_ROLE_PARMS,
		[DRBD_NL_SET_RESIZE_PARMS]	= DRBD_NLA_RESIZE_PARMS,
		[DRBD_NL_SET_START_OV_PARMS]	= DRBD_NLA_START_OV_PARMS,
		[DRBD_NL_SET_NEW_C_UUID_PARMS]	= DRBD_NLA_NEW_C_UUID_PARMS,
		[DRBD_NL_SET_DISCONNECT_PARMS]	= DRBD_NLA_DISCONNECT_PARMS,
		[DRBD_NL_SET_DETACH_PARMS]	= DRBD_NLA_DETACH_PARMS,
	};

	/*
	 * v1 has no NLA_CONNECT_PARMS container: discard_my_data and
	 * tentative arrive inside net_conf and are stashed while
	 * overlaying it, so report whether there is a stashed value.
	 */
	if (set == DRBD_NL_SET_CONNECT_PARMS) {
		struct compat84_req *req = compat84_req(ctx);

		return req->connect_parms_84.has_discard_my_data ||
			req->connect_parms_84.has_tentative;
	}

	if (!tla[set])
		return false;
	return compat84_req(ctx)->info->attrs[tla[set]] != NULL;
}

/*
 * The generated *_from_attrs() parsers fill the vendored v1 wire
 * structs (struct disk_conf, struct net_conf, ...), whose field sets
 * differ from the core's neutral structs, so every set below parses into
 * a local v1 struct and translates field by field into dst.
 *
 * For the persistent config sets (disk_conf, net_conf, res_opts), dst
 * already holds the object's current values. The parser only writes a
 * field whose attribute is present, so the local struct is pre-seeded
 * from dst and copied back whole: an absent attribute round-trips its
 * old value, preserving drbd_nl.h's "absent attributes leave dst
 * untouched" contract. Most one-shot action parms start from a zeroed
 * dst, so a zeroed local struct already matches; resize_parms and
 * start_ov_parms do not, and are pre-seeded the same way.
 *
 * The v1 disk_conf treats backing_dev/meta_dev/meta_dev_idx as required, so
 * a plain disk-options call parses with err == -ENOMSG while every other
 * field is still filled in. drbd_nl.c tolerates -ENOMSG as non-fatal, so
 * each case copies back (and stashes) before returning err, never on an
 * early return.
 */
static int compat84_overlay(struct drbd_adm_ctx *ctx, enum drbd_nl_attr_set set, void *dst)
{
	struct genl_info *info = compat84_req(ctx)->info;
	struct compat84_req *req = compat84_req(ctx);

	switch (set) {
	case DRBD_NL_SET_DISK_CONF: {
		struct drbd_disk_conf *d = dst;
		struct disk_conf c = {
			.meta_dev_idx			= d->meta_dev_idx,
			.disk_size			= d->disk_size,
			.on_io_error			= d->on_io_error,
			.resync_after			= d->resync_after,
			.al_extents			= d->al_extents,
			.disk_barrier			= d->disk_barrier,
			.disk_flushes			= d->disk_flushes,
			.disk_drain			= d->disk_drain,
			.md_flushes			= d->md_flushes,
			.disk_timeout			= d->disk_timeout,
			.read_balancing			= d->read_balancing,
			.al_updates			= d->al_updates,
			.discard_zeroes_if_aligned	= d->discard_zeroes_if_aligned,
			.rs_discard_granularity		= d->rs_discard_granularity,
			.disable_write_same		= d->disable_write_same,
		};
		struct nlattr **ntb;
		int err, ntb_err;

		memcpy(c.backing_dev, d->backing_dev, sizeof(c.backing_dev));
		c.backing_dev_len = d->backing_dev_len;
		memcpy(c.meta_dev, d->meta_dev, sizeof(c.meta_dev));
		c.meta_dev_len = d->meta_dev_len;

		err = disk_conf_from_attrs(&c, info);

		/*
		 * Copy back and stash before returning err: -ENOMSG from a
		 * plain disk-options call (see above) must not discard the
		 * fields it did send. Any other error leaves c at its
		 * pre-seeded values, so copying back is a no-op.
		 */
		memcpy(d->backing_dev, c.backing_dev, sizeof(d->backing_dev));
		d->backing_dev_len = c.backing_dev_len;
		memcpy(d->meta_dev, c.meta_dev, sizeof(d->meta_dev));
		d->meta_dev_len = c.meta_dev_len;
		d->meta_dev_idx = c.meta_dev_idx;
		d->disk_size = c.disk_size;
		d->on_io_error = c.on_io_error;
		d->resync_after = c.resync_after;
		d->al_extents = c.al_extents;
		d->disk_barrier = c.disk_barrier;
		d->disk_flushes = c.disk_flushes;
		d->disk_drain = c.disk_drain;
		d->md_flushes = c.md_flushes;
		d->disk_timeout = c.disk_timeout;
		d->read_balancing = c.read_balancing;
		d->al_updates = c.al_updates;
		d->discard_zeroes_if_aligned = c.discard_zeroes_if_aligned;
		d->rs_discard_granularity = c.rs_discard_granularity;
		d->disable_write_same = c.disable_write_same;
		/* max_bio_bvecs: no DRBD 9 equivalent, dropped. */

		/*
		 * The resync-tuning fields belong to struct drbd_peer_device_conf,
		 * fencing to net_conf.fencing_policy; neither is reachable
		 * through this dst. Re-parse the nested table for per-field
		 * presence and stash them for the attach/disk-options
		 * handlers.
		 */
		ntb_err = disk_conf_ntb_from_attrs(&ntb, info);
		if ((!ntb_err || ntb_err == -ENOMSG) && ntb) {
			req->peer_device_conf_84.resync_rate = c.resync_rate;
			req->peer_device_conf_84.has_resync_rate =
				ntb[DRBD_A_DISK_CONF_RESYNC_RATE] != NULL;
			req->peer_device_conf_84.c_plan_ahead = c.c_plan_ahead;
			req->peer_device_conf_84.has_c_plan_ahead =
				ntb[DRBD_A_DISK_CONF_C_PLAN_AHEAD] != NULL;
			req->peer_device_conf_84.c_delay_target = c.c_delay_target;
			req->peer_device_conf_84.has_c_delay_target =
				ntb[DRBD_A_DISK_CONF_C_DELAY_TARGET] != NULL;
			req->peer_device_conf_84.c_fill_target = c.c_fill_target;
			req->peer_device_conf_84.has_c_fill_target =
				ntb[DRBD_A_DISK_CONF_C_FILL_TARGET] != NULL;
			req->peer_device_conf_84.c_max_rate = c.c_max_rate;
			req->peer_device_conf_84.has_c_max_rate =
				ntb[DRBD_A_DISK_CONF_C_MAX_RATE] != NULL;
			req->peer_device_conf_84.c_min_rate = c.c_min_rate;
			req->peer_device_conf_84.has_c_min_rate =
				ntb[DRBD_A_DISK_CONF_C_MIN_RATE] != NULL;

			req->fencing_policy_84 = c.fencing;
			req->has_fencing_policy_84 =
				ntb[DRBD_A_DISK_CONF_FENCING] != NULL;
		}
		kfree(ntb);

		return err;
	}
	case DRBD_NL_SET_NET_CONF: {
		struct drbd_net_conf *d = dst;
		struct net_conf c = {
			.wire_protocol			= d->wire_protocol,
			.connect_int			= d->connect_int,
			.timeout			= d->timeout,
			.ping_int			= d->ping_int,
			.ping_timeo			= d->ping_timeo,
			.sndbuf_size			= d->sndbuf_size,
			.rcvbuf_size			= d->rcvbuf_size,
			.ko_count			= d->ko_count,
			.max_buffers			= d->max_buffers,
			.max_epoch_size			= d->max_epoch_size,
			.after_sb_0p			= d->after_sb_0p,
			.after_sb_1p			= d->after_sb_1p,
			.after_sb_2p			= d->after_sb_2p,
			.rr_conflict			= d->rr_conflict,
			.on_congestion			= d->on_congestion,
			.cong_fill			= d->cong_fill,
			.cong_extents			= d->cong_extents,
			.two_primaries			= d->two_primaries,
			.tcp_cork			= d->tcp_cork,
			.always_asbp			= d->always_asbp,
			.use_rle			= d->use_rle,
			.csums_after_crash_only		= d->csums_after_crash_only,
			.sock_check_timeo		= d->sock_check_timeo,
		};
		struct nlattr **ntb;
		int err, ntb_err;

		memcpy(c.shared_secret, d->shared_secret, sizeof(c.shared_secret));
		c.shared_secret_len = d->shared_secret_len;
		memcpy(c.cram_hmac_alg, d->cram_hmac_alg, sizeof(c.cram_hmac_alg));
		c.cram_hmac_alg_len = d->cram_hmac_alg_len;
		memcpy(c.integrity_alg, d->integrity_alg, sizeof(c.integrity_alg));
		c.integrity_alg_len = d->integrity_alg_len;
		memcpy(c.verify_alg, d->verify_alg, sizeof(c.verify_alg));
		c.verify_alg_len = d->verify_alg_len;
		memcpy(c.csums_alg, d->csums_alg, sizeof(c.csums_alg));
		c.csums_alg_len = d->csums_alg_len;

		err = net_conf_from_attrs(&c, info);

		/* Copy back and stash before returning err, as for DISK_CONF. */
		memcpy(d->shared_secret, c.shared_secret, sizeof(d->shared_secret));
		d->shared_secret_len = c.shared_secret_len;
		memcpy(d->cram_hmac_alg, c.cram_hmac_alg, sizeof(d->cram_hmac_alg));
		d->cram_hmac_alg_len = c.cram_hmac_alg_len;
		memcpy(d->integrity_alg, c.integrity_alg, sizeof(d->integrity_alg));
		d->integrity_alg_len = c.integrity_alg_len;
		memcpy(d->verify_alg, c.verify_alg, sizeof(d->verify_alg));
		d->verify_alg_len = c.verify_alg_len;
		memcpy(d->csums_alg, c.csums_alg, sizeof(d->csums_alg));
		d->csums_alg_len = c.csums_alg_len;
		d->wire_protocol = c.wire_protocol;
		d->connect_int = c.connect_int;
		d->timeout = c.timeout;
		d->ping_int = c.ping_int;
		d->ping_timeo = c.ping_timeo;
		d->sndbuf_size = c.sndbuf_size;
		d->rcvbuf_size = c.rcvbuf_size;
		d->ko_count = c.ko_count;
		d->max_buffers = c.max_buffers;
		d->max_epoch_size = c.max_epoch_size;
		d->after_sb_0p = c.after_sb_0p;
		d->after_sb_1p = c.after_sb_1p;
		d->after_sb_2p = c.after_sb_2p;
		d->rr_conflict = c.rr_conflict;
		d->on_congestion = c.on_congestion;
		d->cong_fill = c.cong_fill;
		d->cong_extents = c.cong_extents;
		d->two_primaries = c.two_primaries;
		d->tcp_cork = c.tcp_cork;
		d->always_asbp = c.always_asbp;
		d->use_rle = c.use_rle;
		d->csums_after_crash_only = c.csums_after_crash_only;
		d->sock_check_timeo = c.sock_check_timeo;

		/*
		 * fencing is a disk option in 8.4, so "net-options
		 * --set-defaults" must not reset it: keep the live value.
		 * drbd_adm_net_opts() holds conf_update.
		 */
		if (ctx->set_defaults && ctx->connection) {
			struct drbd_net_conf *old;

			rcu_read_lock();
			old = rcu_dereference(ctx->connection->transport.net_conf);
			if (old)
				d->fencing_policy = old->fencing_policy;
			rcu_read_unlock();
		}

		/*
		 * unplug_watermark is dropped: no DRBD 9 code reads it, and
		 * net_conf is connection-scoped while disk_conf, its DRBD 9
		 * home, is per device. discard_my_data/tentative belong to
		 * struct drbd_connect_parms; stash them for the connect handler.
		 */
		ntb_err = net_conf_ntb_from_attrs(&ntb, info);
		if ((!ntb_err || ntb_err == -ENOMSG) && ntb) {
			req->connect_parms_84.discard_my_data = c.discard_my_data;
			req->connect_parms_84.has_discard_my_data =
				ntb[DRBD_A_NET_CONF_DISCARD_MY_DATA] != NULL;
			req->connect_parms_84.tentative = c.tentative;
			req->connect_parms_84.has_tentative =
				ntb[DRBD_A_NET_CONF_TENTATIVE] != NULL;
		}
		kfree(ntb);

		/*
		 * fencing lives in the v1 disk_conf on the wire but in
		 * drbd_net_conf.fencing_policy on DRBD 9. The attach/disk-options
		 * handler stashed it while parsing disk_conf and re-enters
		 * this overlay for NET_CONF once it has the connection. A
		 * real NET_CONF request never has this flag set.
		 */
		if (req->has_fencing_policy_84)
			d->fencing_policy = req->fencing_policy_84;

		/*
		 * DRBD 9 requires a connection name; v1 has no such concept.
		 * Default it only for a freshly created connection (name_len
		 * == 0), matching the name drbd9 drbdsetup's own compat84 shim
		 * passes (--_name=remote).
		 */
		if (!d->name_len) {
			static const char v1_conn_name[] = "remote";

			strscpy(d->name, v1_conn_name, sizeof(d->name));
			d->name_len = strlen(v1_conn_name);
		}

		return err;
	}
	case DRBD_NL_SET_RES_OPTS: {
		struct drbd_res_opts *d = dst;
		struct res_opts c = {
			.on_no_data = d->on_no_data,
		};
		int err;

		memcpy(c.cpu_mask, d->cpu_mask, sizeof(c.cpu_mask));
		c.cpu_mask_len = d->cpu_mask_len;

		err = res_opts_from_attrs(&c, info);

		/*
		 * The other fourteen DRBD 9 res_opts fields have no v1
		 * attribute, so v1's --set-defaults must not reset them
		 * either: that would drop drbd8_compat_mode and
		 * explicit_drbd8_compat and turn auto_promote back on.
		 * drbd_adm_resource_opts() holds adm_mutex, so the live
		 * res_opts are stable here.
		 */
		if (ctx->set_defaults && ctx->resource)
			*d = ctx->resource->res_opts;

		/* Copy back before returning err, as for DISK_CONF. */
		memcpy(d->cpu_mask, c.cpu_mask, sizeof(d->cpu_mask));
		d->cpu_mask_len = c.cpu_mask_len;
		d->on_no_data = c.on_no_data;
		return err;
	}
	case DRBD_NL_SET_SET_ROLE_PARMS: {
		struct drbd_set_role_parms *d = dst;
		struct set_role_parms c = { };
		int err = set_role_parms_from_attrs(&c, info);

		if (err)
			return err;
		/* v1's assume_uptodate is drbd-utils 8.9.x's wire name for --force. */
		d->force = c.assume_uptodate;
		return 0;
	}
	case DRBD_NL_SET_RESIZE_PARMS: {
		struct drbd_resize_parms *d = dst;
		/* drbd_adm_resize() pre-fills the current AL layout. */
		struct resize_parms c = {
			.resize_size = d->resize_size,
			.resize_force = d->resize_force,
			.no_resync = d->no_resync,
			.al_stripes = d->al_stripes,
			.al_stripe_size = d->al_stripe_size,
		};
		int err = resize_parms_from_attrs(&c, info);

		if (err)
			return err;
		d->resize_size = c.resize_size;
		d->resize_force = c.resize_force;
		d->no_resync = c.no_resync;
		d->al_stripes = c.al_stripes;
		d->al_stripe_size = c.al_stripe_size;
		return 0;
	}
	case DRBD_NL_SET_START_OV_PARMS: {
		struct drbd_start_ov_parms *d = dst;
		/* drbd_adm_start_ov() pre-fills the resume position. */
		struct start_ov_parms c = {
			.ov_start_sector = d->ov_start_sector,
			.ov_stop_sector = d->ov_stop_sector,
		};
		int err = start_ov_parms_from_attrs(&c, info);

		if (err)
			return err;
		d->ov_start_sector = c.ov_start_sector;
		d->ov_stop_sector = c.ov_stop_sector;
		return 0;
	}
	case DRBD_NL_SET_NEW_C_UUID_PARMS: {
		struct drbd_new_c_uuid_parms *d = dst;
		struct new_c_uuid_parms c = { };
		int err = new_c_uuid_parms_from_attrs(&c, info);

		if (err)
			return err;
		d->clear_bm = c.clear_bm;
		/* force_resync: DRBD 9 only, no v1 attribute; leave untouched. */
		return 0;
	}
	case DRBD_NL_SET_DISCONNECT_PARMS: {
		struct drbd_disconnect_parms *d = dst;
		struct disconnect_parms c = { };
		int err = disconnect_parms_from_attrs(&c, info);

		if (err)
			return err;
		d->force_disconnect = c.force_disconnect;
		return 0;
	}
	case DRBD_NL_SET_DETACH_PARMS: {
		struct drbd_detach_parms *d = dst;
		struct detach_parms c = { };
		int err = detach_parms_from_attrs(&c, info);

		if (err)
			return err;
		d->force_detach = c.force_detach;
		/* intentional_diskless_detach: DRBD 9 only; leave untouched. */
		return 0;
	}
	case DRBD_NL_SET_PEER_DEVICE_CONF: {
		struct drbd_peer_device_conf *d = dst;

		/*
		 * Not parsed from the wire: the DISK_CONF case stashed these
		 * while parsing the disk_conf that carried them. The
		 * attach/disk-options handler re-enters overlay() for
		 * PEER_DEVICE_CONF once it has the peer device.
		 */
		if (req->peer_device_conf_84.has_resync_rate)
			d->resync_rate = req->peer_device_conf_84.resync_rate;
		if (req->peer_device_conf_84.has_c_plan_ahead)
			d->c_plan_ahead = req->peer_device_conf_84.c_plan_ahead;
		if (req->peer_device_conf_84.has_c_delay_target)
			d->c_delay_target = req->peer_device_conf_84.c_delay_target;
		if (req->peer_device_conf_84.has_c_fill_target)
			d->c_fill_target = req->peer_device_conf_84.c_fill_target;
		if (req->peer_device_conf_84.has_c_max_rate)
			d->c_max_rate = req->peer_device_conf_84.c_max_rate;
		if (req->peer_device_conf_84.has_c_min_rate)
			d->c_min_rate = req->peer_device_conf_84.c_min_rate;

		return 0;
	}
	case DRBD_NL_SET_PATH_PARMS: {
		struct drbd_path_parms *d = dst;

		/*
		 * v1 carries the endpoint addresses in DRBD_NLA_CFG_CONTEXT,
		 * parsed once per request into req; drbd_adm_new_path()
		 * calls here once per path.
		 */
		if (!req->ctx_my_addr_len || !req->ctx_peer_addr_len)
			return -ENOMSG;

		memcpy(d->my_addr, req->ctx_my_addr, req->ctx_my_addr_len);
		d->my_addr_len = req->ctx_my_addr_len;
		memcpy(d->peer_addr, req->ctx_peer_addr, req->ctx_peer_addr_len);
		d->peer_addr_len = req->ctx_peer_addr_len;
		return 0;
	}
	case DRBD_NL_SET_CONNECT_PARMS: {
		struct drbd_connect_parms *d = dst;

		/*
		 * Stashed by the NET_CONF case; dst is a fresh zeroed struct,
		 * so an unsent field already defaults to false.
		 */
		if (req->connect_parms_84.has_discard_my_data)
			d->discard_my_data = req->connect_parms_84.discard_my_data;
		if (req->connect_parms_84.has_tentative)
			d->tentative = req->connect_parms_84.tentative;
		return 0;
	}
	case DRBD_NL_SET_DEVICE_CONF:
	case DRBD_NL_SET_INVALIDATE_PARMS:
	case DRBD_NL_SET_INVALIDATE_PEER_PARMS:
	case DRBD_NL_SET_FORGET_PEER_PARMS:
	case DRBD_NL_SET_RENAME_RESOURCE_PARMS:
	case DRBD_NL_SET_SUSPEND_IO_PARMS:
		/* No v1 counterpart: report a missing required attribute
		 * rather than silently proceeding with defaults.
		 */
		return -ENOMSG;
	case __DRBD_NL_SET_MAX:
		break;
	}
	return -EINVAL;
}

/*
 * The generated parser returns the nested attribute table both on success
 * and on -ENOMSG (some required attrs missing), which is the typical case
 * for a change op since drbdsetup omits the invariant attrs. Inspect and
 * free the table in both cases. It is NULL when the nested container
 * attribute is absent entirely (command without any options).
 */
static bool compat84_attr_present(struct drbd_adm_ctx *ctx, enum drbd_adm_field field)
{
	static const struct {
		int (*ntb_from_attrs)(struct nlattr ***ntb, struct genl_info *info);
		int attr;
		const char *name;
	} invariant[] = {
		[DRBD_ADM_F_DISK_BACKING_DEV] = { disk_conf_ntb_from_attrs,
			DRBD_A_DISK_CONF_BACKING_DEV, "DRBD_A_DISK_CONF_BACKING_DEV" },
		[DRBD_ADM_F_DISK_META_DEV] = { disk_conf_ntb_from_attrs,
			DRBD_A_DISK_CONF_META_DEV, "DRBD_A_DISK_CONF_META_DEV" },
		[DRBD_ADM_F_DISK_META_DEV_IDX] = { disk_conf_ntb_from_attrs,
			DRBD_A_DISK_CONF_META_DEV_IDX, "DRBD_A_DISK_CONF_META_DEV_IDX" },
		[DRBD_ADM_F_DISK_SIZE] = { disk_conf_ntb_from_attrs,
			DRBD_A_DISK_CONF_DISK_SIZE, "DRBD_A_DISK_CONF_DISK_SIZE" },
	};
	struct nlattr **ntb;
	bool found;
	int err;

	/* v1 has no transport name, no load-balance-paths and no explicit
	 * node id: none of these can be an invariant-change attempt.
	 */
	switch (field) {
	case DRBD_ADM_F_NET_TRANSPORT_NAME:
	case DRBD_ADM_F_NET_LOAD_BALANCE_PATHS:
	case DRBD_ADM_F_RES_NODE_ID:
		return false;
	default:
		break;
	}

	err = invariant[field].ntb_from_attrs(&ntb, compat84_req(ctx)->info);
	found = (!err || err == -ENOMSG) && ntb && ntb[invariant[field].attr];
	kfree(ntb);
	if (found)
		pr_info("must not change invariant attr: %s\n", invariant[field].name);
	return found;
}

static int compat84_put_timeout_type(struct drbd_adm_ctx *ctx, enum drbd_timeout_flag type)
{
	struct compat84_req *req = compat84_req(ctx);
	struct timeout_parms tp = { .timeout_type = type };
	int err;

	err = timeout_parms_to_skb(req->reply_skb, &tp);
	if (err) {
		nlmsg_free(req->reply_skb);
		req->reply_skb = NULL;
		return err;
	}
	return NO_ERROR;
}

/*
 * Placeholders. Every notify_ hook below (and, until this commit, every
 * emit_ hook too) is reached from generic code paths that do not check
 * for NULL (the dumps in drbd_nl.c and the unconditional per-dialect
 * fan-out in the drbd_notify_..._state() functions), so a registered
 * dialect can never leave them NULL, no matter how far its own
 * dump/notify support has actually gotten.
 *
 * A later commit replaces the notify_ hooks below with real v1 wire emitters,
 * except notify_path_state, which stays a no-op permanently: DRBD 8.4 has
 * no concept of a path object (that is a multi-path DRBD 9 feature), so
 * there is nothing for the v1 dialect to ever emit here. emit_path is the
 * same permanent no-op, for the same reason.
 */

/*
 * DRBD_NLA_CFG_CONTEXT for a dump row. v1's container carries ctx_volume,
 * ctx_resource_name, ctx_my_addr and ctx_peer_addr (drbd/drbd-84/uapi/
 * linux/drbd_genl.h): no ctx_peer_node_id, no ctx_conn_name (8.4 has
 * neither concept).
 *
 * Unlike the ported nla_put_drbd_cfg_context() this is based on
 * (drbd_nl_legacy.c:823), which takes a "path" argument because DRBD 9's
 * v2 model hangs addresses off a struct drbd_path handed in by the
 * caller, this one takes a "connection" argument instead: 8.4 has no
 * path objects at the *wire* level (v1 has no GET_PATHS;
 * compat84_emit_path() is a permanent no-op), but the v1 model has
 * exactly one address pair per connection, by construction
 * (drbd8_compat_mode caps a resource to one connection, and
 * compat84_resolve_peer_node_id() above relies on that same connection
 * having exactly one transport path). This mirrors mainline's own
 * in-tree 8.4 driver, nla_put_drbd_cfg_context() (drivers/block/drbd/
 * drbd_nl.c), which reads connection->my_addr/peer_addr directly because
 * that tree has no transport/path abstraction at all; here the
 * equivalent datum lives one level down, on the connection's single
 * transport path.
 *
 * Takes its own rcu_read_lock() around the path lookup, the same
 * "narrowly scoped, safe to nest in any caller" idiom
 * nla_put_drbd_cfg_context() (drbd_nl_legacy.c) uses for ctx_conn_name,
 * since not every caller here already holds one (the notify_* hooks
 * below mostly don't at this point in their own function).
 */
static int compat84_put_cfg_context(struct sk_buff *skb, struct drbd_resource *resource,
				    struct drbd_connection *connection,
				    struct drbd_device *device)
{
	struct nlattr *nla;

	nla = nla_nest_start_noflag(skb, DRBD_NLA_CFG_CONTEXT);
	if (!nla)
		goto nla_put_failure;
	if (device)
		nla_put_u32(skb, DRBD_A_DRBD_CFG_CONTEXT_CTX_VOLUME, device->vnr);
	if (resource)
		nla_put_string(skb, DRBD_A_DRBD_CFG_CONTEXT_CTX_RESOURCE_NAME, resource->name);
	if (connection) {
		struct drbd_path *path;

		rcu_read_lock();
		path = list_first_or_null_rcu(&connection->transport.paths,
					      struct drbd_path, list);
		if (path) {
			if (path->my_addr_len)
				nla_put(skb, DRBD_A_DRBD_CFG_CONTEXT_CTX_MY_ADDR,
					path->my_addr_len, &path->my_addr);
			if (path->peer_addr_len)
				nla_put(skb, DRBD_A_DRBD_CFG_CONTEXT_CTX_PEER_ADDR,
					path->peer_addr_len, &path->peer_addr);
		}
		rcu_read_unlock();
	}
	nla_nest_end(skb, nla);
	return 0;

nla_put_failure:
	if (nla)
		nla_nest_cancel(skb, nla);
	return -EMSGSIZE;
}

/*
 * The single peer device of an 8.4-mode device, or NULL if none exists
 * yet. Callers hold rcu_read_lock(). Kept apart from drbd_get_state_84()
 * (drbd_legacy_84.c), which couples the same lookup to a state fetch.
 */
static struct drbd_peer_device *compat84_single_peer_device(struct drbd_device *device)
{
	return list_first_or_null_rcu(&device->peer_devices, struct drbd_peer_device,
				      peer_devices);
}

static int compat84_emit_resource(struct sk_buff *skb, struct netlink_callback *cb,
				  struct drbd_resource *resource,
				  struct drbd_resource_info *info,
				  struct drbd_resource_statistics *statistics)
{
	struct resource_info info_84 = {
		.res_role = info->res_role,
		.res_susp = info->res_susp,
		.res_susp_nod = info->res_susp_nod,
		.res_susp_fen = info->res_susp_fen,
		/* res_susp_quorum, res_fail_io: DRBD 9 only, no v1 attribute. */
	};
	struct resource_statistics statistics_84 = {
		.res_stat_write_ordering = statistics->res_stat_write_ordering,
	};
	struct res_opts res_opts = {
		.on_no_data = resource->res_opts.on_no_data,
	};
	struct drbd_genlmsghdr *dh;
	int err;

	memcpy(res_opts.cpu_mask, resource->res_opts.cpu_mask, sizeof(res_opts.cpu_mask));
	res_opts.cpu_mask_len = resource->res_opts.cpu_mask_len;

	dh = genlmsg_put(skb, NETLINK_CB(cb->skb).portid,
			 cb->nlh->nlmsg_seq, &drbd_nl_family,
			 NLM_F_MULTI, DRBD_ADM_GET_RESOURCES);
	if (!dh)
		return -ENOMEM;
	dh->minor = -1U;
	dh->ret_code = NO_ERROR;
	err = compat84_put_cfg_context(skb, resource, NULL, NULL);
	if (err)
		return err;
	err = res_opts_to_skb(skb, &res_opts);
	if (err)
		return err;
	err = resource_info_to_skb(skb, &info_84);
	if (err)
		return err;
	err = resource_statistics_to_skb(skb, &statistics_84);
	if (err)
		return err;
	genlmsg_end(skb, dh);
	return 0;
}

static int compat84_emit_device(struct sk_buff *skb, struct netlink_callback *cb, int retcode,
				struct drbd_device *device,
				struct drbd_disk_conf *disk_conf,
				struct drbd_device_info *info,
				struct drbd_device_statistics *statistics)
{
	struct drbd_genlmsghdr *dh;
	int err;

	dh = genlmsg_put(skb, NETLINK_CB(cb->skb).portid,
			 cb->nlh->nlmsg_seq, &drbd_nl_family,
			 NLM_F_MULTI, DRBD_ADM_GET_DEVICES);
	if (!dh)
		return -ENOMEM;
	dh->ret_code = retcode;
	dh->minor = -1U;
	if (retcode != NO_ERROR) {
		genlmsg_end(skb, dh);
		return 0;
	}

	dh->minor = device->minor;
	err = compat84_put_cfg_context(skb, device->resource, NULL, device);
	if (err)
		return err;

	/* v1 has no DRBD_NLA_DEVICE_CONF container. */

	if (disk_conf) {
		struct drbd_peer_device *peer_device = compat84_single_peer_device(device);
		struct drbd_peer_device_conf *pdc =
			peer_device ? rcu_dereference(peer_device->conf) : NULL;
		struct drbd_net_conf *nc = peer_device ?
			rcu_dereference(peer_device->connection->transport.net_conf) : NULL;
		struct disk_conf dc = {
			.meta_dev_idx = disk_conf->meta_dev_idx,
			.disk_size = disk_conf->disk_size,
			.on_io_error = disk_conf->on_io_error,
			/*
			 * fencing and the five resync-tuning fields below live
			 * in net_conf.fencing_policy and struct
			 * peer_device_conf on DRBD 9, unreachable from
			 * disk_conf; see compat84_overlay()'s DISK_CONF case
			 * for the write-side twin of this. Neither exists
			 * before a peer device does, so 0 (v1's "unset")
			 * until then.
			 */
			.fencing = nc ? nc->fencing_policy : 0,
			.resync_rate = pdc ? pdc->resync_rate : 0,
			.resync_after = disk_conf->resync_after,
			.al_extents = disk_conf->al_extents,
			.c_plan_ahead = pdc ? pdc->c_plan_ahead : 0,
			.c_delay_target = pdc ? pdc->c_delay_target : 0,
			.c_fill_target = pdc ? pdc->c_fill_target : 0,
			.c_max_rate = pdc ? pdc->c_max_rate : 0,
			.c_min_rate = pdc ? pdc->c_min_rate : 0,
			.disk_barrier = disk_conf->disk_barrier,
			.disk_flushes = disk_conf->disk_flushes,
			.disk_drain = disk_conf->disk_drain,
			.md_flushes = disk_conf->md_flushes,
			.disk_timeout = disk_conf->disk_timeout,
			.read_balancing = disk_conf->read_balancing,
			.al_updates = disk_conf->al_updates,
			.discard_zeroes_if_aligned = disk_conf->discard_zeroes_if_aligned,
			.rs_discard_granularity = disk_conf->rs_discard_granularity,
			.disable_write_same = disk_conf->disable_write_same,
			/* max_bio_bvecs: no DRBD 9 equivalent, left 0 (matches
			 * compat84_overlay()'s DISK_CONF case dropping it on
			 * the write side).
			 */
		};

		memcpy(dc.backing_dev, disk_conf->backing_dev, sizeof(dc.backing_dev));
		dc.backing_dev_len = disk_conf->backing_dev_len;
		memcpy(dc.meta_dev, disk_conf->meta_dev, sizeof(dc.meta_dev));
		dc.meta_dev_len = disk_conf->meta_dev_len;

		err = disk_conf_to_skb(skb, &dc);
		if (err)
			return err;
	}

	{
		struct device_info info_84 = {
			.dev_disk_state = drbd_disk_state_84(info->dev_disk_state),
			/* is_intentional_diskless, dev_has_quorum, dev_is_open,
			 * backing_dev_path: DRBD 9 only, no v1 attribute.
			 */
		};

		err = device_info_to_skb(skb, &info_84);
		if (err)
			return err;
	}
	{
		struct device_statistics stat_84 = {
			.dev_size = statistics->dev_size,
			.dev_read = statistics->dev_read,
			.dev_write = statistics->dev_write,
			.dev_al_writes = statistics->dev_al_writes,
			.dev_bm_writes = statistics->dev_bm_writes,
			.dev_upper_pending = statistics->dev_upper_pending,
			.dev_lower_pending = statistics->dev_lower_pending,
			.dev_upper_blocked = statistics->dev_upper_blocked,
			.dev_lower_blocked = statistics->dev_lower_blocked,
			.dev_al_suspended = statistics->dev_al_suspended,
			.dev_exposed_data_uuid = statistics->dev_exposed_data_uuid,
			.dev_current_uuid = statistics->dev_current_uuid,
			.dev_disk_flags = statistics->dev_disk_flags & MDF_84_MASK,
			.history_uuids_len = statistics->history_uuids_len,
		};

		BUILD_BUG_ON(sizeof(stat_84.history_uuids) != sizeof(statistics->history_uuids));
		memcpy(stat_84.history_uuids, statistics->history_uuids,
		       sizeof(stat_84.history_uuids));

		err = device_statistics_to_skb(skb, &stat_84);
		if (err)
			return err;
	}
	genlmsg_end(skb, dh);
	return 0;
}

/*
 * struct drbd_net_conf -> struct net_conf. Does not mask shared_secret;
 * callers reachable by an unprivileged listener use
 * compat84_put_net_conf_masked(). Shared by GET_CONNECTIONS and
 * GET_STATUS.
 *
 * unplug_watermark has no persistent DRBD 9 home, so it is reported as
 * 8.4's compiled-in default rather than 0: drbdsetup-84 show prints any
 * non-default value, and drbdadm-84 adjust would then reissue
 * net-options --set-defaults on every run. A non-default value
 * configured on genuine 8.4 cannot be reflected back.
 */
static void compat84_pack_net_conf_84(struct net_conf *out, struct drbd_net_conf *net_conf)
{
	*out = (struct net_conf){
		.wire_protocol = net_conf->wire_protocol,
		.unplug_watermark = DRBD_UNPLUG_WATERMARK_DEF,
		.connect_int = net_conf->connect_int,
		.timeout = net_conf->timeout,
		.ping_int = net_conf->ping_int,
		.ping_timeo = net_conf->ping_timeo,
		.sndbuf_size = net_conf->sndbuf_size,
		.rcvbuf_size = net_conf->rcvbuf_size,
		.ko_count = net_conf->ko_count,
		.max_buffers = net_conf->max_buffers,
		.max_epoch_size = net_conf->max_epoch_size,
		.after_sb_0p = net_conf->after_sb_0p,
		.after_sb_1p = net_conf->after_sb_1p,
		.after_sb_2p = net_conf->after_sb_2p,
		.rr_conflict = net_conf->rr_conflict,
		.on_congestion = net_conf->on_congestion,
		.cong_fill = net_conf->cong_fill,
		.cong_extents = net_conf->cong_extents,
		.two_primaries = net_conf->two_primaries,
		.tcp_cork = net_conf->tcp_cork,
		.always_asbp = net_conf->always_asbp,
		.use_rle = net_conf->use_rle,
		.csums_after_crash_only = net_conf->csums_after_crash_only,
		.sock_check_timeo = net_conf->sock_check_timeo,
		/* discard_my_data/tentative: one-shot connect flags, no persistent home. */
	};

	memcpy(out->shared_secret, net_conf->shared_secret, sizeof(out->shared_secret));
	out->shared_secret_len = net_conf->shared_secret_len;
	memcpy(out->cram_hmac_alg, net_conf->cram_hmac_alg, sizeof(out->cram_hmac_alg));
	out->cram_hmac_alg_len = net_conf->cram_hmac_alg_len;
	memcpy(out->integrity_alg, net_conf->integrity_alg, sizeof(out->integrity_alg));
	out->integrity_alg_len = net_conf->integrity_alg_len;
	memcpy(out->verify_alg, net_conf->verify_alg, sizeof(out->verify_alg));
	out->verify_alg_len = net_conf->verify_alg_len;
	memcpy(out->csums_alg, net_conf->csums_alg, sizeof(out->csums_alg));
	out->csums_alg_len = net_conf->csums_alg_len;
}

/*
 * Pack and serialize @net_conf, zeroing the shared secret when
 * @exclude_sensitive: a reply reachable by an unprivileged caller must not
 * carry it (GET_STATUS and GET_CONNECTIONS carry no GENL_ADMIN_PERM).
 */
static int compat84_put_net_conf_masked(struct sk_buff *skb, struct drbd_net_conf *net_conf,
					bool exclude_sensitive)
{
	struct net_conf nc;

	compat84_pack_net_conf_84(&nc, net_conf);
	if (exclude_sensitive) {
		memset(nc.shared_secret, 0, sizeof(nc.shared_secret));
		nc.shared_secret_len = 0;
	}
	return net_conf_to_skb(skb, &nc);
}

static int compat84_emit_connection(struct sk_buff *skb, struct netlink_callback *cb, int retcode,
				    struct drbd_resource *resource,
				    struct drbd_connection *connection,
				    struct drbd_net_conf *net_conf,
				    struct drbd_connection_info *info,
				    struct drbd_connection_statistics *statistics)
{
	struct drbd_genlmsghdr *dh;
	int err;

	dh = genlmsg_put(skb, NETLINK_CB(cb->skb).portid,
			 cb->nlh->nlmsg_seq, &drbd_nl_family,
			 NLM_F_MULTI, DRBD_ADM_GET_CONNECTIONS);
	if (!dh)
		return -ENOMEM;
	dh->ret_code = retcode;
	dh->minor = -1U;
	if (retcode != NO_ERROR) {
		genlmsg_end(skb, dh);
		return 0;
	}

	err = compat84_put_cfg_context(skb, resource, connection, NULL);
	if (err)
		return err;

	/* v1 has no DRBD_NLA_PATH_PARMS container. */

	if (net_conf) {
		/* This dump carries no GENL_ADMIN_PERM. */
		err = compat84_put_net_conf_masked(skb, net_conf, !capable(CAP_SYS_ADMIN));
		if (err)
			return err;
	}
	{
		struct connection_info info_84 = {
			.conn_connection_state = info->conn_connection_state,
			.conn_role = info->conn_role,
		};

		err = connection_info_to_skb(skb, &info_84);
		if (err)
			return err;
	}
	{
		struct connection_statistics stat_84 = {
			.conn_congested = statistics->conn_congested,
			/* ap_in_flight, rs_in_flight: DRBD 9 only, no v1 attribute. */
		};

		err = connection_statistics_to_skb(skb, &stat_84);
		if (err)
			return err;
	}
	genlmsg_end(skb, dh);
	return 0;
}

static int compat84_emit_peer_device(struct sk_buff *skb, struct netlink_callback *cb, int retcode,
				     struct drbd_peer_device *peer_device, unsigned int minor,
				     struct drbd_peer_device_info *info,
				     struct drbd_peer_device_statistics *statistics,
				     struct drbd_peer_device_conf *conf)
{
	struct drbd_genlmsghdr *dh;
	int err;

	dh = genlmsg_put(skb, NETLINK_CB(cb->skb).portid,
			 cb->nlh->nlmsg_seq, &drbd_nl_family,
			 NLM_F_MULTI, DRBD_ADM_GET_PEER_DEVICES);
	if (!dh)
		return -ENOMEM;
	dh->ret_code = retcode;
	dh->minor = -1U;
	if (retcode != NO_ERROR) {
		genlmsg_end(skb, dh);
		return 0;
	}

	dh->minor = minor;
	err = compat84_put_cfg_context(skb, peer_device->device->resource,
					peer_device->connection, peer_device->device);
	if (err)
		return err;

	{
		struct peer_device_info info_84 = {
			.peer_repl_state = info->peer_repl_state,
			.peer_disk_state = drbd_disk_state_84(info->peer_disk_state),
			.peer_resync_susp_user = info->peer_resync_susp_user,
			.peer_resync_susp_peer = info->peer_resync_susp_peer,
			.peer_resync_susp_dependency = info->peer_resync_susp_dependency,
			/* peer_is_intentional_diskless, peer_resync_susp_max_parallel:
			 * DRBD 9 only, no v1 attribute.
			 */
		};

		err = peer_device_info_to_skb(skb, &info_84);
		if (err)
			return err;
	}
	{
		struct peer_device_statistics stat_84 = {
			.peer_dev_received = statistics->peer_dev_received,
			.peer_dev_sent = statistics->peer_dev_sent,
			.peer_dev_pending = statistics->peer_dev_pending,
			.peer_dev_unacked = statistics->peer_dev_unacked,
			.peer_dev_out_of_sync = statistics->peer_dev_out_of_sync,
			.peer_dev_resync_failed = statistics->peer_dev_resync_failed,
			.peer_dev_bitmap_uuid = statistics->peer_dev_bitmap_uuid,
			.peer_dev_flags = statistics->peer_dev_flags & PEER_DEV_FLAGS_84_MASK,
			/* the fifteen resync/OV telemetry fields past this point:
			 * DRBD 9 only, no v1 attribute.
			 */
		};

		err = peer_device_statistics_to_skb(skb, &stat_84);
		if (err)
			return err;
	}

	/*
	 * v1 has no DRBD_NLA_PEER_DEVICE_OPTS container; the resync-tuning
	 * fields ride on GET_DEVICES's disk_conf instead.
	 */

	genlmsg_end(skb, dh);
	return 0;
}

/* Permanent no-op: DRBD 8.4 has no path objects. */
static int compat84_emit_path(struct sk_buff *skb, struct netlink_callback *cb, int retcode,
			      struct drbd_resource *resource, struct drbd_connection *connection,
			      struct drbd_path *path, struct drbd_nl_path_info *info)
{
	return 0;
}

static int compat84_notify_resource_state(struct sk_buff *skb, unsigned int seq,
					  struct drbd_resource *resource,
					  struct drbd_resource_info *info,
					  struct drbd_rename_resource_info *rename_info,
					  enum drbd_notification_type type)
{
	return 0;
}

static int compat84_notify_device_state(struct sk_buff *skb, unsigned int seq,
					struct drbd_device *device,
					struct drbd_device_info *info,
					enum drbd_notification_type type)
{
	return 0;
}

static int compat84_notify_connection_state(struct sk_buff *skb, unsigned int seq,
					    struct drbd_connection *connection,
					    struct drbd_connection_info *info,
					    enum drbd_notification_type type)
{
	return 0;
}

static int compat84_notify_peer_device_state(struct sk_buff *skb, unsigned int seq,
					     struct drbd_peer_device *peer_device,
					     struct drbd_peer_device_info *info,
					     enum drbd_notification_type type)
{
	return 0;
}

/* Permanent no-op: DRBD 8.4 has no path objects. */
static int compat84_notify_path_state(struct sk_buff *skb, unsigned int seq,
				      struct drbd_connection *connection, struct drbd_path *path,
				      struct drbd_nl_path_info *info,
				      enum drbd_notification_type type)
{
	return 0;
}

static int compat84_notify_helper(struct sk_buff *skb, unsigned int seq,
				  struct drbd_device *device, struct drbd_connection *connection,
				  const char *name, int status,
				  enum drbd_notification_type type)
{
	return 0;
}

static int compat84_notify_initial_state_done(struct sk_buff *skb, unsigned int seq)
{
	return 0;
}

static const struct drbd_nl_dialect drbd_nl_84_dialect = {
	.name = "drbd-8.4",
	.has_set = compat84_has_set,
	.overlay = compat84_overlay,
	.attr_present = compat84_attr_present,
	.put_timeout_type = compat84_put_timeout_type,
	/*
	 * notify_* below are still placeholders so that the unconditional
	 * notify fan-out never calls through a NULL pointer; see the comment
	 * above. A later commit replaces all but notify_path_state with real
	 * emitters.
	 */
	.emit_resource = compat84_emit_resource,
	.emit_device = compat84_emit_device,
	.emit_connection = compat84_emit_connection,
	.emit_peer_device = compat84_emit_peer_device,
	.emit_path = compat84_emit_path,
	.notify_resource_state = compat84_notify_resource_state,
	.notify_device_state = compat84_notify_device_state,
	.notify_connection_state = compat84_notify_connection_state,
	.notify_peer_device_state = compat84_notify_peer_device_state,
	.notify_path_state = compat84_notify_path_state,
	.notify_helper = compat84_notify_helper,
	.notify_initial_state_done = compat84_notify_initial_state_done,
};

int drbd_adm_dump_devices_done(struct netlink_callback *cb)
{
	return drbd_dump_devices_done(cb);
}

int drbd_adm_dump_connections_done(struct netlink_callback *cb)
{
	return drbd_dump_connections_done(cb);
}

int drbd_adm_dump_peer_devices_done(struct netlink_callback *cb)
{
	return drbd_dump_peer_devices_done(cb);
}

/*
 * Ported from drbd_nl_legacy.c: dump callbacks run outside genl_lock(),
 * so they cannot use the attribute parsing that relies on global tables.
 * The attribute type numbers are the same in both dialects.
 */
static struct nlattr *compat84_find_cfg_context_attr(const struct nlmsghdr *nlh, int attr)
{
	const unsigned int hdrlen = GENL_HDRLEN + sizeof(struct drbd_genlmsghdr);
	struct nlattr *nla;

	nla = nla_find(nlmsg_attrdata(nlh, hdrlen), nlmsg_attrlen(nlh, hdrlen),
		       DRBD_NLA_CFG_CONTEXT);
	if (!nla)
		return NULL;
	return nla_find_nested(nla, attr);
}

/*
 * Resolve the optional resource-name filter of a dump on its first call.
 * The core expects the resource in cb->args[0], with a reference that the
 * matching _done callback drops again. Returns true when the name is not
 * known: no resource to walk, the caller reports that in its message.
 */
static bool compat84_dump_filter(struct netlink_callback *cb, int holder_nr)
{
	struct drbd_resource *resource;
	struct nlattr *resource_filter;

	resource_filter =
		compat84_find_cfg_context_attr(cb->nlh, DRBD_A_DRBD_CFG_CONTEXT_CTX_RESOURCE_NAME);
	if (IS_ERR_OR_NULL(resource_filter))
		return false;
	resource = drbd_find_resource(nla_data(resource_filter));
	if (!resource)
		return true;
	kref_debug_get(&resource->kref_debug, holder_nr);
	cb->args[0] = (long)resource;
	return false;
}

int drbd_nl_get_status_doit(struct sk_buff *skb, struct genl_info *info)
{
	return -EOPNOTSUPP;
}

int drbd_nl_get_status_dumpit(struct sk_buff *skb, struct netlink_callback *cb)
{
	return -EOPNOTSUPP;
}

/*
 * Core functions such as drbd_adm_net_opts() and adm_disconnect() index
 * compat84_req(ctx)->info->attrs[] unconditionally, sized to whichever v1
 * command allocated this request. A synthetic re-entry on behalf of a
 * different command (the fencing re-entry below, connect's rollback) can
 * index past the end of that array, a real general protection fault.
 * Substitute a full-sized, all-absent attrs[] for the call: every
 * has_set()/attr_present() then reports "not sent", which is right for a
 * re-entry that feeds its values through req's stashed fields.
 *
 * Also clear adm_ctx->set_defaults for the call. drbd_adm_net_opts()
 * honours it unconditionally, and in 8.4 fencing is a disk option, so
 * "disk-options --set-defaults --fencing=..." (which drbdadm-84 adjust
 * issues routinely) would otherwise reset the whole net_conf, shared
 * secret included, while reporting success.
 *
 * Not used for the drbd_adm_peer_device_opts() re-entries: the
 * resync-tuning fields genuinely live in disk_conf on 8.4, so
 * "disk-options --set-defaults" is supposed to reset them too.
 */
static void compat84_call_with_empty_attrs(struct drbd_adm_ctx *ctx,
					    int (*fn)(struct drbd_adm_ctx *))
{
	struct compat84_req *req = compat84_req(ctx);
	struct nlattr *no_attrs[__DRBD_NLA_MAX] = { };
	struct genl_info empty_info = *req->info;
	struct genl_info *orig_info = req->info;
	bool orig_set_defaults = ctx->set_defaults;

	empty_info.attrs = no_attrs;
	req->info = &empty_info;
	ctx->set_defaults = false;
	fn(ctx);
	ctx->set_defaults = orig_set_defaults;
	req->info = orig_info;
}

/*
 * Apply the resync-tuning and fencing values compat84_overlay() stashed
 * out of disk_conf, after drbd_adm_attach() or drbd_adm_disk_opts()
 * succeeded. 8.4's normal order is attach, then connect, so the peer
 * device (for struct drbd_peer_device_conf) and the connection (for
 * net_conf.fencing_policy) usually do not exist yet; then the values are
 * deferred onto the device and the resource for the connect handler.
 */
/*
 * In 8.4, the resync tuning fields and fencing are disk options, so
 * "disk-options --set-defaults" resets the ones it does not send. They are
 * applied only as sent fields here, so turn the unsent ones into sent
 * defaults.
 */
static void compat84_disk_conf_stash_defaults(struct compat84_req *req)
{
	typeof(req->peer_device_conf_84) *pdc = &req->peer_device_conf_84;

#define STASH_DEFAULT(field, def)		\
	do {					\
		if (!pdc->has_##field) {	\
			pdc->field = def;	\
			pdc->has_##field = true; \
		}				\
	} while (0)
	STASH_DEFAULT(resync_rate, DRBD_RESYNC_RATE_DEF);
	STASH_DEFAULT(c_plan_ahead, DRBD_C_PLAN_AHEAD_DEF);
	STASH_DEFAULT(c_delay_target, DRBD_C_DELAY_TARGET_DEF);
	STASH_DEFAULT(c_fill_target, DRBD_C_FILL_TARGET_DEF);
	STASH_DEFAULT(c_max_rate, DRBD_C_MAX_RATE_DEF);
	STASH_DEFAULT(c_min_rate, DRBD_C_MIN_RATE_DEF);
#undef STASH_DEFAULT

	if (!req->has_fencing_policy_84) {
		req->fencing_policy_84 = DRBD_FENCING_DEF;
		req->has_fencing_policy_84 = true;
	}
}

static void compat84_apply_disk_conf_stash(struct drbd_adm_ctx *ctx)
{
	struct compat84_req *req = compat84_req(ctx);
	struct drbd_device *device = ctx->device;
	struct drbd_resource *resource = device->resource;
	struct drbd_peer_device *peer_device;
	bool have_resync;

	if (ctx->set_defaults)
		compat84_disk_conf_stash_defaults(req);

	have_resync = req->peer_device_conf_84.has_resync_rate ||
		      req->peer_device_conf_84.has_c_plan_ahead ||
		      req->peer_device_conf_84.has_c_delay_target ||
		      req->peer_device_conf_84.has_c_fill_target ||
		      req->peer_device_conf_84.has_c_max_rate ||
		      req->peer_device_conf_84.has_c_min_rate;

	if (!have_resync && !req->has_fencing_policy_84)
		return;

	/*
	 * A connection creates a peer device for every existing device, so
	 * a peer device exists if and only if a connection does.
	 */
retry:
	rcu_read_lock();
	peer_device = list_first_or_null_rcu(&device->peer_devices,
					      struct drbd_peer_device,
					      peer_devices);
	if (peer_device) {
		kref_get(&peer_device->connection->kref);
		kref_debug_get(&peer_device->connection->kref_debug, 2);
	}
	rcu_read_unlock();

	if (!peer_device) {
		mutex_lock(&resource->adm_mutex);
		/*
		 * A connect may have created the peer device meanwhile; it
		 * consumes the stash only afterwards, so stash only while
		 * there still is none, under adm_mutex.
		 */
		if (!list_empty(&device->peer_devices)) {
			mutex_unlock(&resource->adm_mutex);
			goto retry;
		}
		if (have_resync) {
			typeof(req->peer_device_conf_84) *from = &req->peer_device_conf_84;
			typeof(device->pending_peer_device_conf_84) *to =
				&device->pending_peer_device_conf_84;

			if (from->has_resync_rate) {
				to->resync_rate = from->resync_rate;
				to->has_resync_rate = true;
			}
			if (from->has_c_plan_ahead) {
				to->c_plan_ahead = from->c_plan_ahead;
				to->has_c_plan_ahead = true;
			}
			if (from->has_c_delay_target) {
				to->c_delay_target = from->c_delay_target;
				to->has_c_delay_target = true;
			}
			if (from->has_c_fill_target) {
				to->c_fill_target = from->c_fill_target;
				to->has_c_fill_target = true;
			}
			if (from->has_c_max_rate) {
				to->c_max_rate = from->c_max_rate;
				to->has_c_max_rate = true;
			}
			if (from->has_c_min_rate) {
				to->c_min_rate = from->c_min_rate;
				to->has_c_min_rate = true;
			}
		}
		if (req->has_fencing_policy_84) {
			resource->pending_fencing_policy_84 =
				(enum drbd_fencing_policy)req->fencing_policy_84;
			resource->pending_fencing_policy_84_set = true;
		}
		mutex_unlock(&resource->adm_mutex);
		return;
	}

	ctx->connection = peer_device->connection;

	if (have_resync) {
		ctx->peer_device = peer_device;
		drbd_adm_peer_device_opts(ctx);
	}

	if (req->has_fencing_policy_84 && (!have_resync || ctx->result == NO_ERROR))
		compat84_call_with_empty_attrs(ctx, drbd_adm_net_opts);
}

int drbd_nl_new_minor_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_adm_ctx *ctx = info->user_ptr[0];

	if (!compat84_req(ctx)->reply_skb)
		return 0;
	return drbd_adm_new_minor(ctx);
}

int drbd_nl_del_minor_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_adm_ctx *ctx = info->user_ptr[0];

	if (!compat84_req(ctx)->reply_skb)
		return 0;
	return drbd_adm_del_minor(ctx);
}

int drbd_nl_new_resource_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_adm_ctx *ctx = info->user_ptr[0];

	if (!compat84_req(ctx)->reply_skb)
		return 0;
	/*
	 * Every resource created through the version 1 dialect is a DRBD 8.4
	 * resource: single peer, node ids derived from the peer's. The core
	 * enforces that from res_opts.drbd8_compat_mode.
	 */
	ctx->force_drbd8_compat = true;
	return drbd_adm_new_resource(ctx);
}

int drbd_nl_del_resource_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_adm_ctx *ctx = info->user_ptr[0];

	if (!compat84_req(ctx)->reply_skb)
		return 0;
	return drbd_adm_del_resource(ctx);
}

int drbd_nl_resource_opts_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_adm_ctx *ctx = info->user_ptr[0];

	if (!compat84_req(ctx)->reply_skb)
		return 0;
	return drbd_adm_resource_opts(ctx);
}

/*
 * Render a raw sockaddr into the "af:addr:port" / "af:[addr]:port" text
 * drbdadm-84 passes to drbdsetup-84. The kernel only sees the parsed
 * sockaddr, so this reproduces the canonical form, not whatever a user
 * typed by hand.
 */
static int compat84_addr_to_str(char *buf, size_t size, const u8 *addr, u32 addr_len)
{
	const struct sockaddr *sa = (const struct sockaddr *)addr;

	if (addr_len >= sizeof(struct sockaddr_in6) && sa->sa_family == AF_INET6) {
		const struct sockaddr_in6 *a6 = (const struct sockaddr_in6 *)addr;

		return scnprintf(buf, size, "ipv6:[%pI6c]:%u",
				  &a6->sin6_addr, ntohs(a6->sin6_port));
	}
	if (addr_len >= sizeof(struct sockaddr_in) && sa->sa_family == AF_INET) {
		const struct sockaddr_in *a4 = (const struct sockaddr_in *)addr;

		return scnprintf(buf, size, "ipv4:%pI4:%u",
				  &a4->sin_addr, ntohs(a4->sin_port));
	}
	return -EINVAL;
}

/*
 * v1's connect carries only an address pair; DRBD 9 needs a peer node id.
 * drbd9's own compat84 shim (user/v9/drbdsetup_compat84.c, compare_addr())
 * invents one when it drives one end of a mixed deployment, and this must
 * match it: node ids are baked into the on-disk metadata slot layout, so
 * disagreeing is a data-integrity hazard, not just a failed connect.
 *
 * The rule: crc32c(0x1a656f21, "af:addr:port") for both addresses; the
 * larger hash gets node id 1. Both ends apply it to the same inputs, so
 * the results are always complementary. drbd-utils keeps the hashes in an
 * int, so "larger" is a signed comparison.
 */
static int compat84_connect_peer_node_id(struct compat84_req *req, u32 *peer_node_id)
{
	char my_str[64], peer_str[64];
	int my_len, peer_len;
	u32 my_hash, peer_hash;

	if (!req->ctx_my_addr_len || !req->ctx_peer_addr_len)
		return -EINVAL;

	my_len = compat84_addr_to_str(my_str, sizeof(my_str),
				       req->ctx_my_addr, req->ctx_my_addr_len);
	peer_len = compat84_addr_to_str(peer_str, sizeof(peer_str),
					 req->ctx_peer_addr, req->ctx_peer_addr_len);
	if (my_len < 0 || peer_len < 0)
		return -EINVAL;

	my_hash = crc32c(0x1a656f21, my_str, my_len);
	peer_hash = crc32c(0x1a656f21, peer_str, peer_len);
	if (my_hash == peer_hash)
		return -EINVAL;

	*peer_node_id = ((s32)my_hash > (s32)peer_hash) ? 0 : 1;
	return 0;
}

/* The per-device half of compat84_apply_pending_stash(); @device is referenced. */
static void compat84_apply_pending_resync(struct drbd_adm_ctx *ctx,
					  struct drbd_device *device)
{
	struct compat84_req *req = compat84_req(ctx);
	struct drbd_resource *resource = device->resource;
	struct drbd_peer_device *peer_device;
	bool have_resync;

	if (mutex_lock_interruptible(&resource->adm_mutex))
		return;
	have_resync = device->pending_peer_device_conf_84.has_resync_rate ||
		      device->pending_peer_device_conf_84.has_c_plan_ahead ||
		      device->pending_peer_device_conf_84.has_c_delay_target ||
		      device->pending_peer_device_conf_84.has_c_fill_target ||
		      device->pending_peer_device_conf_84.has_c_max_rate ||
		      device->pending_peer_device_conf_84.has_c_min_rate;
	if (have_resync) {
		/* Two distinct anonymous struct types: copy field by field. */
		req->peer_device_conf_84.has_resync_rate =
			device->pending_peer_device_conf_84.has_resync_rate;
		req->peer_device_conf_84.resync_rate =
			device->pending_peer_device_conf_84.resync_rate;
		req->peer_device_conf_84.has_c_plan_ahead =
			device->pending_peer_device_conf_84.has_c_plan_ahead;
		req->peer_device_conf_84.c_plan_ahead =
			device->pending_peer_device_conf_84.c_plan_ahead;
		req->peer_device_conf_84.has_c_delay_target =
			device->pending_peer_device_conf_84.has_c_delay_target;
		req->peer_device_conf_84.c_delay_target =
			device->pending_peer_device_conf_84.c_delay_target;
		req->peer_device_conf_84.has_c_fill_target =
			device->pending_peer_device_conf_84.has_c_fill_target;
		req->peer_device_conf_84.c_fill_target =
			device->pending_peer_device_conf_84.c_fill_target;
		req->peer_device_conf_84.has_c_max_rate =
			device->pending_peer_device_conf_84.has_c_max_rate;
		req->peer_device_conf_84.c_max_rate =
			device->pending_peer_device_conf_84.c_max_rate;
		req->peer_device_conf_84.has_c_min_rate =
			device->pending_peer_device_conf_84.has_c_min_rate;
		req->peer_device_conf_84.c_min_rate =
			device->pending_peer_device_conf_84.c_min_rate;
	}
	mutex_unlock(&resource->adm_mutex);

	if (!have_resync)
		return;

	rcu_read_lock();
	peer_device = list_first_or_null_rcu(&device->peer_devices,
					      struct drbd_peer_device,
					      peer_devices);
	rcu_read_unlock();
	if (!peer_device)
		return;

	/* drbd_adm_peer_device_opts() takes resource->adm_mutex
	 * itself; must not be held here.
	 */
	ctx->peer_device = peer_device;
	drbd_adm_peer_device_opts(ctx);
	ctx->peer_device = NULL;

	if (ctx->result == NO_ERROR) {
		if (!mutex_lock_interruptible(&resource->adm_mutex)) {
			memset(&device->pending_peer_device_conf_84, 0,
			       sizeof(device->pending_peer_device_conf_84));
			mutex_unlock(&resource->adm_mutex);
		}
	} else {
		drbd_warn(device,
			  "could not apply deferred 8.4 resync tuning after connect\n");
	}
}

/*
 * The other end of compat84_apply_disk_conf_stash(): apply the deferred
 * values now that connect has created the connection and a peer device
 * for every volume. A failure here does not undo the connect; the values
 * are retried on the next connect.
 */
static void compat84_apply_pending_stash(struct drbd_adm_ctx *ctx)
{
	struct compat84_req *req = compat84_req(ctx);
	struct drbd_resource *resource = ctx->resource;
	struct drbd_device *device;
	int vnr;

	/*
	 * The per-device step sleeps on adm_mutex; hold a device reference
	 * across it so a concurrent del-minor cannot free the device.
	 */
	rcu_read_lock();
	idr_for_each_entry(&resource->devices, device, vnr) {
		kref_get(&device->kref);
		rcu_read_unlock();
		compat84_apply_pending_resync(ctx, device);
		kref_put(&device->kref, drbd_destroy_device);
		rcu_read_lock();
	}
	rcu_read_unlock();

	if (!resource->pending_fencing_policy_84_set)
		return;

	if (mutex_lock_interruptible(&resource->adm_mutex))
		return;
	req->fencing_policy_84 = resource->pending_fencing_policy_84;
	req->has_fencing_policy_84 = true;
	mutex_unlock(&resource->adm_mutex);

	/*
	 * Routed through compat84_call_with_empty_attrs() like the fencing
	 * re-entry in compat84_apply_disk_conf_stash(): a client may set
	 * --set-defaults on connect too.
	 */
	compat84_call_with_empty_attrs(ctx, drbd_adm_net_opts);
	req->has_fencing_policy_84 = false;

	if (ctx->result == NO_ERROR) {
		if (!mutex_lock_interruptible(&resource->adm_mutex)) {
			resource->pending_fencing_policy_84_set = false;
			mutex_unlock(&resource->adm_mutex);
		}
	} else {
		drbd_warn(resource, "could not apply deferred 8.4 fencing policy after connect\n");
	}
}

/*
 * v1's single CONNECT carries what DRBD 9 splits into new-peer, new-path
 * and connect; drbdsetup-84 has no commands to issue them separately.
 *
 * drbd_adm_new_peer()/_new_path()/_connect() report their outcome in
 * ctx->result, and drbd_adm_connect()'s success path writes an enum
 * drbd_state_rv there on top of the enum drbd_ret_code its failure paths
 * use, so success is the same range check drbd_adm_down() relies on, not
 * "== NO_ERROR".
 */
static bool compat84_result_ok(int result)
{
	return result >= SS_SUCCESS && result <= NO_ERROR;
}

/*
 * A v1 disconnect deletes the connection's path (8.4 forgets the
 * connection's addresses once it is StandAlone) but keeps the connection
 * and its peer devices, so the next connect has to pick it up again.
 * Returns that path-less connection's peer node id, or -1 if there is none.
 */
static int compat84_pathless_peer_node_id(struct drbd_resource *resource)
{
	struct drbd_connection *connection;
	int peer_node_id = -1;

	rcu_read_lock();
	connection = list_first_or_null_rcu(&resource->connections,
					     struct drbd_connection, connections);
	if (connection && list_empty(&connection->transport.paths))
		peer_node_id = connection->peer_node_id;
	rcu_read_unlock();

	return peer_node_id;
}

int drbd_nl_connect_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_adm_ctx *ctx = info->user_ptr[0];
	struct compat84_req *req = compat84_req(ctx);
	struct drbd_connection *connection;
	bool reused, path_added = false, node_ids_unset;
	int pathless_id;
	u32 peer_node_id;

	if (!req->reply_skb)
		return 0;

	/* new-path assigns the node ids of an 8.4 resource on its first connect. */
	mutex_lock(&ctx->resource->adm_mutex);
	node_ids_unset = ctx->resource->res_opts.node_id == -1;
	mutex_unlock(&ctx->resource->adm_mutex);

	pathless_id = compat84_pathless_peer_node_id(ctx->resource);
	reused = pathless_id >= 0;
	if (reused) {
		peer_node_id = pathless_id;
	} else if (compat84_connect_peer_node_id(req, &peer_node_id)) {
		drbd_adm_msg(ctx, "%s",
			     "could not determine a peer node id from the given addresses");
		ctx->result = ERR_INVALID_REQUEST;
		return 0;
	}
	ctx->peer_node_id = peer_node_id;

	if (!reused) {
		drbd_adm_new_peer(ctx);
		if (!compat84_result_ok(ctx->result))
			return 0;
	}

	/*
	 * drbd_adm_new_peer() only creates the connection; look it up the
	 * way drbd_adm_ctx_resolve() would, so the calls below and
	 * drbd_adm_ctx_release() see a normally resolved request.
	 */
	connection = drbd_get_connection_by_node_id(ctx->resource, peer_node_id);
	if (!connection) {
		/*
		 * Cannot happen: nothing else removes a connection this
		 * request just created under adm_mutex. ctx->connection is
		 * still NULL, so drbd_adm_del_peer() has nothing to act on.
		 */
		drbd_adm_msg(ctx, "%s", "internal error: new peer vanished");
		ctx->result = ERR_INVALID_REQUEST;
		return 0;
	}
	kref_debug_get(&connection->kref_debug, 2);
	ctx->connection = connection;

	/* A reused connection still has the previous connect's net options. */
	if (reused)
		drbd_adm_net_opts(ctx);
	if (compat84_result_ok(ctx->result)) {
		drbd_adm_new_path(ctx);
		path_added = compat84_result_ok(ctx->result);
	}
	if (path_added)
		drbd_adm_connect(ctx);

	if (!compat84_result_ok(ctx->result)) {
		int result = ctx->result;

		if (!reused) {
			/*
			 * v1 has no del-peer, so a failed connect must not leave a
			 * peer behind: tear down whatever of {peer, path} was
			 * created. adm_disconnect() reads an attrs[] index
			 * CONNECT's policy does not carry, hence
			 * compat84_call_with_empty_attrs().
			 */
			compat84_call_with_empty_attrs(ctx, drbd_adm_del_peer);
			/*
			 * Unassign the node ids again, or a retry with other
			 * addresses keeps the ones derived from these.
			 */
			if (node_ids_unset) {
				mutex_lock(&ctx->resource->adm_mutex);
				if (list_empty(&ctx->resource->connections))
					ctx->resource->res_opts.node_id = -1;
				mutex_unlock(&ctx->resource->adm_mutex);
			}
		} else if (path_added) {
			/* Back to the path-less state the last disconnect left. */
			drbd_adm_del_path(ctx);
		}
		ctx->result = result;
		return 0;
	}

	/*
	 * The connect succeeded and that is what the reply reports;
	 * compat84_apply_pending_stash() writes its own outcomes to
	 * ctx->result.
	 */
	compat84_apply_pending_stash(ctx);
	ctx->result = NO_ERROR;
	return 0;
}

int drbd_nl_disconnect_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_adm_ctx *ctx = info->user_ptr[0];

	if (!compat84_req(ctx)->reply_skb)
		return 0;
	drbd_adm_disconnect(ctx);
	if (!compat84_result_ok(ctx->result))
		return 0;

	/*
	 * 8.4 forgets a StandAlone connection's addresses, so that the next
	 * connect may name different ones; do the same by deleting the path.
	 * drbd_nl_connect_doit() then reuses the path-less connection.
	 */
	drbd_adm_del_path(ctx);
	return 0;
}

int drbd_nl_attach_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_adm_ctx *ctx = info->user_ptr[0];

	if (!compat84_req(ctx)->reply_skb)
		return 0;
	drbd_adm_attach(ctx);
	if (ctx->result == NO_ERROR)
		compat84_apply_disk_conf_stash(ctx);
	return 0;
}

int drbd_nl_resize_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_adm_ctx *ctx = info->user_ptr[0];

	if (!compat84_req(ctx)->reply_skb)
		return 0;
	return drbd_adm_resize(ctx);
}

int drbd_nl_primary_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_adm_ctx *ctx = info->user_ptr[0];

	if (!compat84_req(ctx)->reply_skb)
		return 0;
	return drbd_adm_primary(ctx);
}

int drbd_nl_secondary_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_adm_ctx *ctx = info->user_ptr[0];

	if (!compat84_req(ctx)->reply_skb)
		return 0;
	return drbd_adm_secondary(ctx);
}

int drbd_nl_new_c_uuid_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_adm_ctx *ctx = info->user_ptr[0];

	if (!compat84_req(ctx)->reply_skb)
		return 0;
	return drbd_adm_new_c_uuid(ctx);
}

int drbd_nl_start_ov_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_adm_ctx *ctx = info->user_ptr[0];

	if (!compat84_req(ctx)->reply_skb)
		return 0;
	return drbd_adm_start_ov(ctx);
}

/* True if no device in @resource has a live disk. */
static bool compat84_resource_has_no_disk(struct drbd_resource *resource)
{
	struct drbd_device *d;
	int vnr;
	bool none = true;

	rcu_read_lock();
	idr_for_each_entry(&resource->devices, d, vnr) {
		if (get_ldev_if_state(d, D_FAILED)) {
			put_ldev(d);
			none = false;
			break;
		}
	}
	rcu_read_unlock();
	return none;
}

int drbd_nl_detach_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_adm_ctx *ctx = info->user_ptr[0];
	struct drbd_device *device = ctx->device;
	struct drbd_resource *resource = ctx->resource;

	if (!compat84_req(ctx)->reply_skb)
		return 0;
	drbd_adm_detach(ctx);
	if (ctx->result == NO_ERROR) {
		/*
		 * Bound the stashes to the attach that produced them, or a
		 * detach without ever connecting followed by an attach that
		 * does not resend them would still apply the old values on
		 * the next connect. The resync-tuning stash is per device.
		 * The fencing stash is per resource, and a multi-volume 8.4
		 * resource must not lose it when one volume detaches, so
		 * clear it only once no device has a disk left.
		 */
		mutex_lock(&resource->adm_mutex);
		memset(&device->pending_peer_device_conf_84, 0,
		       sizeof(device->pending_peer_device_conf_84));
		if (compat84_resource_has_no_disk(resource))
			resource->pending_fencing_policy_84_set = false;
		mutex_unlock(&resource->adm_mutex);
	}
	return 0;
}

int drbd_nl_invalidate_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_adm_ctx *ctx = info->user_ptr[0];

	if (!compat84_req(ctx)->reply_skb)
		return 0;
	return drbd_adm_invalidate(ctx);
}

int drbd_nl_inval_peer_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_adm_ctx *ctx = info->user_ptr[0];

	if (!compat84_req(ctx)->reply_skb)
		return 0;
	return drbd_adm_invalidate_peer(ctx);
}

int drbd_nl_pause_sync_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_adm_ctx *ctx = info->user_ptr[0];

	if (!compat84_req(ctx)->reply_skb)
		return 0;
	return drbd_adm_pause_sync(ctx);
}

int drbd_nl_resume_sync_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_adm_ctx *ctx = info->user_ptr[0];

	if (!compat84_req(ctx)->reply_skb)
		return 0;
	return drbd_adm_resume_sync(ctx);
}

int drbd_nl_suspend_io_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_adm_ctx *ctx = info->user_ptr[0];

	if (!compat84_req(ctx)->reply_skb)
		return 0;
	return drbd_adm_suspend_io(ctx);
}

int drbd_nl_resume_io_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_adm_ctx *ctx = info->user_ptr[0];

	if (!compat84_req(ctx)->reply_skb)
		return 0;
	return drbd_adm_resume_io(ctx);
}

int drbd_nl_outdate_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_adm_ctx *ctx = info->user_ptr[0];

	if (!compat84_req(ctx)->reply_skb)
		return 0;
	return drbd_adm_outdate(ctx);
}

int drbd_nl_get_timeout_type_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_adm_ctx *ctx = info->user_ptr[0];

	if (!compat84_req(ctx)->reply_skb)
		return 0;
	return drbd_adm_get_timeout_type(ctx);
}

int drbd_nl_down_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_adm_ctx *ctx = info->user_ptr[0];

	if (!compat84_req(ctx)->reply_skb)
		return 0;
	return drbd_adm_down(ctx);
}

int drbd_nl_chg_disk_opts_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_adm_ctx *ctx = info->user_ptr[0];

	if (!compat84_req(ctx)->reply_skb)
		return 0;
	drbd_adm_disk_opts(ctx);
	if (ctx->result == NO_ERROR)
		compat84_apply_disk_conf_stash(ctx);
	return 0;
}

int drbd_nl_chg_net_opts_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_adm_ctx *ctx = info->user_ptr[0];

	if (!compat84_req(ctx)->reply_skb)
		return 0;
	return drbd_adm_net_opts(ctx);
}

int drbd_nl_get_resources_dumpit(struct sk_buff *skb, struct netlink_callback *cb)
{
	return drbd_dump_resources(skb, cb, &drbd_nl_84_dialect);
}

int drbd_nl_get_devices_dumpit(struct sk_buff *skb, struct netlink_callback *cb)
{
	if (!cb->args[0] && !cb->args[1] && compat84_dump_filter(cb, 7)) {
		int err = compat84_emit_device(skb, cb, ERR_RES_NOT_KNOWN,
					       NULL, NULL, NULL, NULL);

		return err ? err : skb->len;
	}
	return drbd_dump_devices(skb, cb, &drbd_nl_84_dialect);
}

int drbd_nl_get_connections_dumpit(struct sk_buff *skb, struct netlink_callback *cb)
{
	if (!cb->args[0]) {
		if (compat84_dump_filter(cb, 6)) {
			int err = compat84_emit_connection(skb, cb, ERR_RES_NOT_KNOWN,
							   NULL, NULL, NULL, NULL, NULL);

			return err ? err : skb->len;
		}
		if (cb->args[0])
			cb->args[1] = DRBD_DUMP_SINGLE_RESOURCE;
	}
	return drbd_dump_connections(skb, cb, &drbd_nl_84_dialect);
}

int drbd_nl_get_peer_devices_dumpit(struct sk_buff *skb, struct netlink_callback *cb)
{
	if (!cb->args[0] && !cb->args[1] && compat84_dump_filter(cb, 9)) {
		int err = compat84_emit_peer_device(skb, cb, ERR_RES_NOT_KNOWN,
						    NULL, 0, NULL, NULL, NULL);

		return err ? err : skb->len;
	}
	return drbd_dump_peer_devices(skb, cb, &drbd_nl_84_dialect);
}

int drbd_nl_get_initial_state_dumpit(struct sk_buff *skb, struct netlink_callback *cb)
{
	return -EOPNOTSUPP;
}

int drbd_nl_legacy_init(void)
{
	int err = genl_register_family(&drbd_nl_family);

	if (err)
		return err;
	err = drbd_nl_register_dialect(&drbd_nl_84_dialect);
	if (err)
		genl_unregister_family(&drbd_nl_family);
	return err;
}

void drbd_nl_legacy_exit(void)
{
	genl_unregister_family(&drbd_nl_family);
}
