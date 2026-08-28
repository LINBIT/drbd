// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 1999-2008, Philipp Reisner <philipp.reisner@linbit.com>.
 * Copyright (C) 2002-2008, Lars Ellenberg <lars.ellenberg@linbit.com>.
 * Copyright (C) 2001-2008, LINBIT Information Technologies GmbH.
 * Copyright (C) 2008, LINBIT HA-Solutions GmbH.
 */

/*
 * The legacy "drbd" generic netlink family: everything that knows about
 * the bytes on the wire of that dialect. The command implementations
 * themselves live in drbd_nl.c and only ever see a struct drbd_adm_ctx.
 */

#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt

#include <linux/slab.h>
#include <linux/drbd.h>
#include <net/genetlink.h>
#include <net/sock.h>

#include "drbd_int.h"
#include "drbd_nl.h"

/* Per-request state of the legacy dialect; hangs off drbd_adm_ctx.req. */
struct legacy_req {
	struct genl_info *info;
	struct sk_buff *reply_skb;
	struct drbd_genlmsghdr *reply_dh;
};

/* One allocation for both, so that pre_doit zeroes the context only once. */
struct legacy_ctx {
	struct drbd_adm_ctx ctx;
	struct legacy_req req;
};

static inline struct legacy_req *legacy_req(struct drbd_adm_ctx *ctx)
{
	return ctx->req;
}

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

/* Serialize ctx->result and ctx->msg[] into the legacy reply. */
static void legacy_put_outcome(struct drbd_adm_ctx *ctx)
{
	struct legacy_req *req = legacy_req(ctx);
	const char *p, *end;

	req->reply_dh->ret_code = ctx->result;
	for (p = ctx->msg, end = ctx->msg + ctx->msg_len; p < end; p += strlen(p) + 1)
		drbd_msg_put_info(req->reply_skb, p);
}

static bool need_sys_admin(u8 cmd)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(drbd_nl_ops); i++)
		if (drbd_nl_ops[i].cmd == cmd)
			return 0 != (drbd_nl_ops[i].flags & GENL_ADMIN_PERM);
	return true;
}

static const unsigned int drbd_genl_cmd_flags[] = {
	[DRBD_ADM_NEW_MINOR]       = DRBD_ADM_NEED_RESOURCE,
	[DRBD_ADM_DEL_MINOR]       = DRBD_ADM_NEED_MINOR,
	[DRBD_ADM_NEW_RESOURCE]    = 0,
	[DRBD_ADM_DEL_RESOURCE]    = DRBD_ADM_NEED_RESOURCE,
	[DRBD_ADM_RESOURCE_OPTS]   = DRBD_ADM_NEED_RESOURCE,
	[DRBD_ADM_CONNECT]         = DRBD_ADM_NEED_CONNECTION,
	[DRBD_ADM_DISCONNECT]      = DRBD_ADM_NEED_CONNECTION,
	[DRBD_ADM_ATTACH]          = DRBD_ADM_NEED_MINOR,
	[DRBD_ADM_RESIZE]          = DRBD_ADM_NEED_MINOR,
	[DRBD_ADM_PRIMARY]         = DRBD_ADM_NEED_RESOURCE,
	[DRBD_ADM_SECONDARY]       = DRBD_ADM_NEED_RESOURCE,
	[DRBD_ADM_NEW_C_UUID]      = DRBD_ADM_NEED_MINOR,
	[DRBD_ADM_START_OV]        = DRBD_ADM_NEED_PEER_DEVICE,
	[DRBD_ADM_DETACH]          = DRBD_ADM_NEED_MINOR,
	[DRBD_ADM_INVALIDATE]      = DRBD_ADM_NEED_MINOR,
	[DRBD_ADM_INVALIDATE_PEER] = DRBD_ADM_NEED_PEER_DEVICE,
	[DRBD_ADM_PAUSE_SYNC]      = DRBD_ADM_NEED_PEER_DEVICE,
	[DRBD_ADM_RESUME_SYNC]     = DRBD_ADM_NEED_PEER_DEVICE,
	[DRBD_ADM_SUSPEND_IO]      = DRBD_ADM_NEED_MINOR,
	[DRBD_ADM_RESUME_IO]       = DRBD_ADM_NEED_MINOR,
	[DRBD_ADM_OUTDATE]         = DRBD_ADM_NEED_MINOR,
	[DRBD_ADM_GET_TIMEOUT_TYPE] = DRBD_ADM_NEED_PEER_DEVICE,
	[DRBD_ADM_DOWN]            = DRBD_ADM_NEED_RESOURCE | DRBD_ADM_IGNORE_VERSION,
	[DRBD_ADM_DISK_OPTS]       = DRBD_ADM_NEED_MINOR,
	[DRBD_ADM_NET_OPTS]        = DRBD_ADM_NEED_CONNECTION,
	[DRBD_ADM_GET_RESOURCES]   = 0,
	[DRBD_ADM_GET_DEVICES]     = 0,
	[DRBD_ADM_GET_CONNECTIONS] = 0,
	[DRBD_ADM_GET_PEER_DEVICES] = 0,
	[DRBD_ADM_GET_INITIAL_STATE] = 0,
	[DRBD_ADM_FORGET_PEER]     = DRBD_ADM_NEED_RESOURCE,
	[DRBD_ADM_PEER_DEVICE_OPTS] = DRBD_ADM_NEED_PEER_DEVICE,
	[DRBD_ADM_NEW_PEER]        = DRBD_ADM_NEED_PEER_NODE,
	[DRBD_ADM_NEW_PATH]        = DRBD_ADM_NEED_CONNECTION,
	[DRBD_ADM_DEL_PEER]        = DRBD_ADM_NEED_CONNECTION,
	[DRBD_ADM_DEL_PATH]        = DRBD_ADM_NEED_CONNECTION,
	[DRBD_ADM_RENAME_RESOURCE] = DRBD_ADM_NEED_RESOURCE,
	[DRBD_ADM_GET_PATHS]       = 0,
};

/*
 * Highest nested attribute type the kernel knows for each top-level
 * attribute, for drbd_check_mandatory(). Kept apart from the netlink
 * policies: kernels before v4.20 take .len of an NLA_NESTED entry as a
 * minimum payload length, so the policies cannot carry it.
 */
static const u16 drbd_tla_nested_max[__DRBD_NLA_MAX] = {
	[DRBD_NLA_CFG_REPLY]			= DRBD_A_DRBD_CFG_REPLY_MAX,
	[DRBD_NLA_CFG_CONTEXT]			= DRBD_A_DRBD_CFG_CONTEXT_MAX,
	[DRBD_NLA_DISK_CONF]			= DRBD_A_DISK_CONF_MAX,
	[DRBD_NLA_RESOURCE_OPTS]		= DRBD_A_RES_OPTS_MAX,
	[DRBD_NLA_NET_CONF]			= DRBD_A_NET_CONF_MAX,
	[DRBD_NLA_SET_ROLE_PARMS]		= DRBD_A_SET_ROLE_PARMS_MAX,
	[DRBD_NLA_RESIZE_PARMS]			= DRBD_A_RESIZE_PARMS_MAX,
	[DRBD_NLA_START_OV_PARMS]		= DRBD_A_START_OV_PARMS_MAX,
	[DRBD_NLA_NEW_C_UUID_PARMS]		= DRBD_A_NEW_C_UUID_PARMS_MAX,
	[DRBD_NLA_TIMEOUT_PARMS]		= DRBD_A_TIMEOUT_PARMS_MAX,
	[DRBD_NLA_DISCONNECT_PARMS]		= DRBD_A_DISCONNECT_PARMS_MAX,
	[DRBD_NLA_DETACH_PARMS]			= DRBD_A_DETACH_PARMS_MAX,
	[DRBD_NLA_DEVICE_CONF]			= DRBD_A_DEVICE_CONF_MAX,
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
	[DRBD_NLA_INVALIDATE_PARMS]		= DRBD_A_INVALIDATE_PARMS_MAX,
	[DRBD_NLA_FORGET_PEER_PARMS]		= DRBD_A_FORGET_PEER_PARMS_MAX,
	[DRBD_NLA_PEER_DEVICE_OPTS]		= DRBD_A_PEER_DEVICE_CONF_MAX,
	[DRBD_NLA_PATH_PARMS]			= DRBD_A_PATH_PARMS_MAX,
	[DRBD_NLA_CONNECT_PARMS]		= DRBD_A_CONNECT_PARMS_MAX,
	[DRBD_NLA_PATH_INFO]			= DRBD_A_DRBD_PATH_INFO_MAX,
	[DRBD_NLA_RENAME_RESOURCE_PARMS]	= DRBD_A_RENAME_RESOURCE_PARMS_MAX,
	[DRBD_NLA_RENAME_RESOURCE_INFO]		= DRBD_A_RENAME_RESOURCE_INFO_MAX,
	[DRBD_NLA_INVAL_PEER_PARAMS]		= DRBD_A_INVALIDATE_PEER_PARMS_MAX,
	[DRBD_NLA_SUSPEND_IO_PARAMS]		= DRBD_A_SUSPEND_IO_PARMS_MAX,
};

/* Strip DRBD_GENLA_F_MANDATORY from nested attrs before standard parsing.
 * Reject unknown attrs that had the mandatory bit set.
 */
static int drbd_check_mandatory(const struct genl_split_ops *ops,
				struct genl_info *info)
{
	int i;

	for (i = 0; i <= ops->maxattr && i < ARRAY_SIZE(drbd_tla_nested_max); i++) {
		struct nlattr *tla = info->attrs[i];
		struct nlattr *nla;
		int rem;

		if (!tla || !drbd_tla_nested_max[i])
			continue;

		nla_for_each_nested(nla, tla, rem) {
			if (nla->nla_type & DRBD_GENLA_F_MANDATORY) {
				nla->nla_type &= ~DRBD_GENLA_F_MANDATORY;
				if (nla_type(nla) > drbd_tla_nested_max[i])
					return -EOPNOTSUPP;
			}
		}
	}
	return 0;
}

/*
 * Allocates the command context together with the legacy request state,
 * stores it in info->user_ptr[0], prepares the reply skb and resolves the
 * objects the command refers to. Rejects unknown netlink versions with
 * -EINVAL.
 */
int drbd_pre_doit(const struct genl_split_ops *ops,
			 struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_genlmsghdr *d_in = genl_info_userhdr(info);
	const u8 cmd = info->genlhdr->cmd;
	struct drbd_adm_ctx *adm_ctx;
	struct legacy_ctx *lctx;
	struct legacy_req *req;
	unsigned int flags;
	int err;

	err = drbd_check_mandatory(ops, info);
	if (err)
		return err;

	/* Look up per-command flags */
	flags = (cmd < ARRAY_SIZE(drbd_genl_cmd_flags)) ? drbd_genl_cmd_flags[cmd] : 0;

	if (info->genlhdr->version != DRBD_FAMILY_VERSION && !(flags & DRBD_ADM_IGNORE_VERSION))
		return -EINVAL;

	/*
	 * genl_rcv_msg() only checks if commands with the GENL_ADMIN_PERM flag
	 * set have CAP_NET_ADMIN; we also require CAP_SYS_ADMIN for
	 * administrative commands.
	 */
	if (need_sys_admin(cmd) && !capable(CAP_SYS_ADMIN))
		return -EPERM;

	lctx = kzalloc_obj(struct legacy_ctx);
	if (!lctx)
		return -ENOMEM;

	adm_ctx = &lctx->ctx;
	req = &lctx->req;
	adm_ctx->d = &drbd_nl_legacy_dialect;
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
		nla = nested_attr_tb[DRBD_A_DRBD_CFG_CONTEXT_CTX_PEER_NODE_ID];
		if (nla)
			adm_ctx->peer_node_id = nla_get_u32(nla);
		nla = nested_attr_tb[DRBD_A_DRBD_CFG_CONTEXT_CTX_RESOURCE_NAME];
		if (nla)
			adm_ctx->resource_name = nla_data(nla);
		kfree(nested_attr_tb);
	}

	if (drbd_adm_ctx_resolve(adm_ctx, flags) != NO_ERROR) {
		/* Send error reply now; NULL reply_skb so the handler bails
		 * out. post_doit will drop the kref references.
		 */
		legacy_put_outcome(adm_ctx);
		drbd_adm_send_reply(req->reply_skb, info);
		req->reply_skb = NULL;
	}

	info->user_ptr[0] = adm_ctx;
	return 0;

fail:
	/* Fatal error while preparing the reply; nothing is resolved yet. */
	nlmsg_free(req->reply_skb);
	kfree(lctx);
	info->user_ptr[0] = NULL;
	return err;
}

/*
 * Sends the reply, drops the references acquired while resolving, and
 * frees the context.
 */
void drbd_post_doit(const struct genl_split_ops *ops,
			   struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_adm_ctx *adm_ctx = info->user_ptr[0];
	struct legacy_req *req;

	if (!adm_ctx)
		return;

	req = legacy_req(adm_ctx);
	if (req->reply_skb) {
		legacy_put_outcome(adm_ctx);
		drbd_adm_send_reply(req->reply_skb, info);
	}

	drbd_adm_ctx_release(adm_ctx);
	kfree(container_of(adm_ctx, struct legacy_ctx, ctx));
}

static bool legacy_has_set(struct drbd_adm_ctx *ctx, enum drbd_nl_attr_set set)
{
	static const u16 tla[__DRBD_NL_SET_MAX] = {
		[DRBD_NL_SET_DISK_CONF]			= DRBD_NLA_DISK_CONF,
		[DRBD_NL_SET_NET_CONF]			= DRBD_NLA_NET_CONF,
		[DRBD_NL_SET_RES_OPTS]			= DRBD_NLA_RESOURCE_OPTS,
		[DRBD_NL_SET_PEER_DEVICE_CONF]		= DRBD_NLA_PEER_DEVICE_OPTS,
		[DRBD_NL_SET_DEVICE_CONF]		= DRBD_NLA_DEVICE_CONF,
		[DRBD_NL_SET_SET_ROLE_PARMS]		= DRBD_NLA_SET_ROLE_PARMS,
		[DRBD_NL_SET_RESIZE_PARMS]		= DRBD_NLA_RESIZE_PARMS,
		[DRBD_NL_SET_START_OV_PARMS]		= DRBD_NLA_START_OV_PARMS,
		[DRBD_NL_SET_NEW_C_UUID_PARMS]		= DRBD_NLA_NEW_C_UUID_PARMS,
		[DRBD_NL_SET_DISCONNECT_PARMS]		= DRBD_NLA_DISCONNECT_PARMS,
		[DRBD_NL_SET_DETACH_PARMS]		= DRBD_NLA_DETACH_PARMS,
		[DRBD_NL_SET_INVALIDATE_PARMS]		= DRBD_NLA_INVALIDATE_PARMS,
		[DRBD_NL_SET_INVALIDATE_PEER_PARMS]	= DRBD_NLA_INVAL_PEER_PARAMS,
		[DRBD_NL_SET_FORGET_PEER_PARMS]		= DRBD_NLA_FORGET_PEER_PARMS,
		[DRBD_NL_SET_CONNECT_PARMS]		= DRBD_NLA_CONNECT_PARMS,
		[DRBD_NL_SET_PATH_PARMS]		= DRBD_NLA_PATH_PARMS,
		[DRBD_NL_SET_RENAME_RESOURCE_PARMS]	= DRBD_NLA_RENAME_RESOURCE_PARMS,
		[DRBD_NL_SET_SUSPEND_IO_PARMS]		= DRBD_NLA_SUSPEND_IO_PARAMS,
	};

	return legacy_req(ctx)->info->attrs[tla[set]] != NULL;
}

static int legacy_overlay(struct drbd_adm_ctx *ctx, enum drbd_nl_attr_set set, void *dst)
{
	struct genl_info *info = legacy_req(ctx)->info;

	switch (set) {
	case DRBD_NL_SET_DISK_CONF:		return disk_conf_from_attrs(dst, info);
	case DRBD_NL_SET_NET_CONF:		return net_conf_from_attrs(dst, info);
	case DRBD_NL_SET_RES_OPTS:		return res_opts_from_attrs(dst, info);
	case DRBD_NL_SET_PEER_DEVICE_CONF:	return peer_device_conf_from_attrs(dst, info);
	case DRBD_NL_SET_DEVICE_CONF:		return device_conf_from_attrs(dst, info);
	case DRBD_NL_SET_SET_ROLE_PARMS:	return set_role_parms_from_attrs(dst, info);
	case DRBD_NL_SET_RESIZE_PARMS:		return resize_parms_from_attrs(dst, info);
	case DRBD_NL_SET_START_OV_PARMS:	return start_ov_parms_from_attrs(dst, info);
	case DRBD_NL_SET_NEW_C_UUID_PARMS:	return new_c_uuid_parms_from_attrs(dst, info);
	case DRBD_NL_SET_DISCONNECT_PARMS:	return disconnect_parms_from_attrs(dst, info);
	case DRBD_NL_SET_DETACH_PARMS:		return detach_parms_from_attrs(dst, info);
	case DRBD_NL_SET_INVALIDATE_PARMS:	return invalidate_parms_from_attrs(dst, info);
	case DRBD_NL_SET_INVALIDATE_PEER_PARMS:	return invalidate_peer_parms_from_attrs(dst, info);
	case DRBD_NL_SET_FORGET_PEER_PARMS:	return forget_peer_parms_from_attrs(dst, info);
	case DRBD_NL_SET_CONNECT_PARMS:		return connect_parms_from_attrs(dst, info);
	case DRBD_NL_SET_PATH_PARMS:		return path_parms_from_attrs(dst, info);
	case DRBD_NL_SET_RENAME_RESOURCE_PARMS:	return rename_resource_parms_from_attrs(dst, info);
	case DRBD_NL_SET_SUSPEND_IO_PARMS:	return suspend_io_parms_from_attrs(dst, info);
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
 *
 * The core asks about one field at a time, so this deliberately re-parses
 * the nested attribute table per query (at most four times per request).
 * That mirrors the single has_invariant() || chain it replaces: the chain
 * short-circuits at the first field that is present, and so exactly one
 * pr_info() is emitted, for that field. Do not turn this into a cached
 * parse without preserving that short-circuit -- caching the table and
 * checking all fields would log every present invariant instead of the
 * first one.
 */
static bool legacy_attr_present(struct drbd_adm_ctx *ctx, enum drbd_adm_field field)
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
		[DRBD_ADM_F_NET_TRANSPORT_NAME] = { net_conf_ntb_from_attrs,
			DRBD_A_NET_CONF_TRANSPORT_NAME, "DRBD_A_NET_CONF_TRANSPORT_NAME" },
		[DRBD_ADM_F_NET_LOAD_BALANCE_PATHS] = { net_conf_ntb_from_attrs,
			DRBD_A_NET_CONF_LOAD_BALANCE_PATHS, "DRBD_A_NET_CONF_LOAD_BALANCE_PATHS" },
		[DRBD_ADM_F_RES_NODE_ID] = { res_opts_ntb_from_attrs,
			DRBD_A_RES_OPTS_NODE_ID, "DRBD_A_RES_OPTS_NODE_ID" },
	};
	struct nlattr **ntb;
	bool found;
	int err;

	err = invariant[field].ntb_from_attrs(&ntb, legacy_req(ctx)->info);
	found = (!err || err == -ENOMSG) && ntb && ntb[invariant[field].attr];
	kfree(ntb);
	if (found)
		pr_info("must not change invariant attr: %s\n", invariant[field].name);
	return found;
}

static int legacy_put_timeout_type(struct drbd_adm_ctx *ctx, enum drbd_timeout_flag type)
{
	struct legacy_req *req = legacy_req(ctx);
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

const struct drbd_nl_dialect drbd_nl_legacy_dialect = {
	.name = "drbd",
	.has_set = legacy_has_set,
	.overlay = legacy_overlay,
	.attr_present = legacy_attr_present,
	.put_timeout_type = legacy_put_timeout_type,
};

/*
 * The generated-name entry points. Each unpacks the context prepared by
 * drbd_pre_doit() and calls into the wire-format independent command
 * implementation in drbd_nl.c.
 */

int drbd_nl_new_minor_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_adm_ctx *ctx = info->user_ptr[0];

	if (!legacy_req(ctx)->reply_skb)
		return 0;
	return drbd_adm_new_minor(ctx);
}

int drbd_nl_del_minor_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_adm_ctx *ctx = info->user_ptr[0];

	if (!legacy_req(ctx)->reply_skb)
		return 0;
	return drbd_adm_del_minor(ctx);
}

int drbd_nl_new_resource_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_adm_ctx *ctx = info->user_ptr[0];

	if (!legacy_req(ctx)->reply_skb)
		return 0;
	return drbd_adm_new_resource(ctx);
}

int drbd_nl_del_resource_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_adm_ctx *ctx = info->user_ptr[0];

	if (!legacy_req(ctx)->reply_skb)
		return 0;
	return drbd_adm_del_resource(ctx);
}

int drbd_nl_resource_opts_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_adm_ctx *ctx = info->user_ptr[0];

	if (!legacy_req(ctx)->reply_skb)
		return 0;
	return drbd_adm_resource_opts(ctx);
}

int drbd_nl_connect_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_adm_ctx *ctx = info->user_ptr[0];

	if (!legacy_req(ctx)->reply_skb)
		return 0;
	return drbd_adm_connect(ctx);
}

int drbd_nl_disconnect_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_adm_ctx *ctx = info->user_ptr[0];

	if (!legacy_req(ctx)->reply_skb)
		return 0;
	return drbd_adm_disconnect(ctx);
}

int drbd_nl_attach_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_adm_ctx *ctx = info->user_ptr[0];

	if (!legacy_req(ctx)->reply_skb)
		return 0;
	return drbd_adm_attach(ctx);
}

int drbd_nl_resize_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_adm_ctx *ctx = info->user_ptr[0];

	if (!legacy_req(ctx)->reply_skb)
		return 0;
	return drbd_adm_resize(ctx);
}

int drbd_nl_primary_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_adm_ctx *ctx = info->user_ptr[0];

	if (!legacy_req(ctx)->reply_skb)
		return 0;
	return drbd_adm_primary(ctx);
}

int drbd_nl_secondary_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_adm_ctx *ctx = info->user_ptr[0];

	if (!legacy_req(ctx)->reply_skb)
		return 0;
	return drbd_adm_secondary(ctx);
}

int drbd_nl_new_c_uuid_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_adm_ctx *ctx = info->user_ptr[0];

	if (!legacy_req(ctx)->reply_skb)
		return 0;
	return drbd_adm_new_c_uuid(ctx);
}

int drbd_nl_start_ov_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_adm_ctx *ctx = info->user_ptr[0];

	if (!legacy_req(ctx)->reply_skb)
		return 0;
	return drbd_adm_start_ov(ctx);
}

int drbd_nl_detach_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_adm_ctx *ctx = info->user_ptr[0];

	if (!legacy_req(ctx)->reply_skb)
		return 0;
	return drbd_adm_detach(ctx);
}

int drbd_nl_invalidate_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_adm_ctx *ctx = info->user_ptr[0];

	if (!legacy_req(ctx)->reply_skb)
		return 0;
	return drbd_adm_invalidate(ctx);
}

int drbd_nl_invalidate_peer_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_adm_ctx *ctx = info->user_ptr[0];

	if (!legacy_req(ctx)->reply_skb)
		return 0;
	return drbd_adm_invalidate_peer(ctx);
}

int drbd_nl_pause_sync_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_adm_ctx *ctx = info->user_ptr[0];

	if (!legacy_req(ctx)->reply_skb)
		return 0;
	return drbd_adm_pause_sync(ctx);
}

int drbd_nl_resume_sync_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_adm_ctx *ctx = info->user_ptr[0];

	if (!legacy_req(ctx)->reply_skb)
		return 0;
	return drbd_adm_resume_sync(ctx);
}

int drbd_nl_suspend_io_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_adm_ctx *ctx = info->user_ptr[0];

	if (!legacy_req(ctx)->reply_skb)
		return 0;
	return drbd_adm_suspend_io(ctx);
}

int drbd_nl_resume_io_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_adm_ctx *ctx = info->user_ptr[0];

	if (!legacy_req(ctx)->reply_skb)
		return 0;
	return drbd_adm_resume_io(ctx);
}

int drbd_nl_outdate_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_adm_ctx *ctx = info->user_ptr[0];

	if (!legacy_req(ctx)->reply_skb)
		return 0;
	return drbd_adm_outdate(ctx);
}

int drbd_nl_down_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_adm_ctx *ctx = info->user_ptr[0];

	if (!legacy_req(ctx)->reply_skb)
		return 0;
	return drbd_adm_down(ctx);
}

int drbd_nl_disk_opts_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_adm_ctx *ctx = info->user_ptr[0];

	if (!legacy_req(ctx)->reply_skb)
		return 0;
	return drbd_adm_disk_opts(ctx);
}

int drbd_nl_net_opts_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_adm_ctx *ctx = info->user_ptr[0];

	if (!legacy_req(ctx)->reply_skb)
		return 0;
	return drbd_adm_net_opts(ctx);
}

int drbd_nl_forget_peer_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_adm_ctx *ctx = info->user_ptr[0];

	if (!legacy_req(ctx)->reply_skb)
		return 0;
	return drbd_adm_forget_peer(ctx);
}

int drbd_nl_peer_device_opts_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_adm_ctx *ctx = info->user_ptr[0];

	if (!legacy_req(ctx)->reply_skb)
		return 0;
	return drbd_adm_peer_device_opts(ctx);
}

int drbd_nl_new_peer_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_adm_ctx *ctx = info->user_ptr[0];

	if (!legacy_req(ctx)->reply_skb)
		return 0;
	return drbd_adm_new_peer(ctx);
}

int drbd_nl_new_path_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_adm_ctx *ctx = info->user_ptr[0];

	if (!legacy_req(ctx)->reply_skb)
		return 0;
	return drbd_adm_new_path(ctx);
}

int drbd_nl_del_peer_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_adm_ctx *ctx = info->user_ptr[0];

	if (!legacy_req(ctx)->reply_skb)
		return 0;
	return drbd_adm_del_peer(ctx);
}

int drbd_nl_del_path_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_adm_ctx *ctx = info->user_ptr[0];

	if (!legacy_req(ctx)->reply_skb)
		return 0;
	return drbd_adm_del_path(ctx);
}

int drbd_nl_rename_resource_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_adm_ctx *ctx = info->user_ptr[0];

	if (!legacy_req(ctx)->reply_skb)
		return 0;
	return drbd_adm_rename_resource(ctx);
}

/*
 * This command puts a payload into the reply itself. If that fails, the
 * dialect has already freed the reply skb, so post_doit sends nothing.
 */
int drbd_nl_get_timeout_type_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_adm_ctx *ctx = info->user_ptr[0];

	if (!legacy_req(ctx)->reply_skb)
		return 0;
	return drbd_adm_get_timeout_type(ctx);
}
