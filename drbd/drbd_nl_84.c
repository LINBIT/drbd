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
	 * already exist. v1's connect wire carries a resource name
	 * (CTX_RESOURCE_AND_CONNECTION in drbdsetup(8.4)'s command table),
	 * which is enough: drbd_nl_connect_doit() derives the peer node
	 * id itself, from the address pair, and sequences new-peer/
	 * new-path/connect.
	 */
	[DRBD_ADM_CONNECT]         = DRBD_ADM_NEED_RESOURCE,
	[DRBD_ADM_DISCONNECT]      = DRBD_ADM_NEED_CONNECTION,
	[DRBD_ADM_ATTACH]          = DRBD_ADM_NEED_MINOR,
	[DRBD_ADM_RESIZE]          = DRBD_ADM_NEED_MINOR,
	[DRBD_ADM_PRIMARY]         = DRBD_ADM_NEED_RESOURCE,
	[DRBD_ADM_SECONDARY]       = DRBD_ADM_NEED_RESOURCE,
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
		/*
		 * v1's DRBD_NLA_CFG_CONTEXT has no ctx_peer_node_id (8.4
		 * resources have at most one peer connection): leave
		 * adm_ctx->peer_node_id at PEER_NODE_ID_UNSPECIFIED.
		 */
		kfree(nested_attr_tb);
	}

	if (drbd_adm_ctx_resolve(adm_ctx, flags) != NO_ERROR) {
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
	return false;
}

static int compat84_overlay(struct drbd_adm_ctx *ctx, enum drbd_nl_attr_set set, void *dst)
{
	return -EINVAL;
}

static bool compat84_attr_present(struct drbd_adm_ctx *ctx, enum drbd_adm_field field)
{
	return false;
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
 * Placeholders. Every emit_ and notify_ hook below is reached from
 * generic code paths that do not check for NULL (the dumps in
 * drbd_nl.c and the unconditional per-dialect fan-out in the
 * drbd_notify_..._state() functions), so a registered dialect can
 * never leave them NULL, no matter how far its own dump/notify support
 * has actually gotten.
 *
 * Later commits replace all of these except emit_path and
 * notify_path_state with real v1 wire emitters. Those two stay no-ops
 * permanently: DRBD 8.4 has no concept of a path object (that is a
 * multi-path DRBD 9 feature), so there is nothing for the v1 dialect to
 * ever emit here.
 */

static int compat84_emit_resource(struct sk_buff *skb, struct netlink_callback *cb,
				  struct drbd_resource *resource,
				  struct drbd_resource_info *info,
				  struct drbd_resource_statistics *statistics)
{
	return 0;
}

static int compat84_emit_device(struct sk_buff *skb, struct netlink_callback *cb, int retcode,
				struct drbd_device *device,
				struct drbd_disk_conf *disk_conf,
				struct drbd_device_info *info,
				struct drbd_device_statistics *statistics)
{
	return 0;
}

static int compat84_emit_connection(struct sk_buff *skb, struct netlink_callback *cb, int retcode,
				    struct drbd_resource *resource,
				    struct drbd_connection *connection,
				    struct drbd_net_conf *net_conf,
				    struct drbd_connection_info *info,
				    struct drbd_connection_statistics *statistics)
{
	return 0;
}

static int compat84_emit_peer_device(struct sk_buff *skb, struct netlink_callback *cb, int retcode,
				     struct drbd_peer_device *peer_device, unsigned int minor,
				     struct drbd_peer_device_info *info,
				     struct drbd_peer_device_statistics *statistics,
				     struct drbd_peer_device_conf *conf)
{
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
	 * Placeholders so that the unconditional dump/notify fan-out never
	 * calls through a NULL pointer; see the comment above. Later commits
	 * replace all but emit_path/notify_path_state with real
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
	return 0;
}

int drbd_adm_dump_connections_done(struct netlink_callback *cb)
{
	return 0;
}

int drbd_adm_dump_peer_devices_done(struct netlink_callback *cb)
{
	return 0;
}

int drbd_nl_get_status_doit(struct sk_buff *skb, struct genl_info *info)
{
	return -EOPNOTSUPP;
}

int drbd_nl_get_status_dumpit(struct sk_buff *skb, struct netlink_callback *cb)
{
	return -EOPNOTSUPP;
}

int drbd_nl_new_minor_doit(struct sk_buff *skb, struct genl_info *info)
{
	return -EOPNOTSUPP;
}

int drbd_nl_del_minor_doit(struct sk_buff *skb, struct genl_info *info)
{
	return -EOPNOTSUPP;
}

int drbd_nl_new_resource_doit(struct sk_buff *skb, struct genl_info *info)
{
	return -EOPNOTSUPP;
}

int drbd_nl_del_resource_doit(struct sk_buff *skb, struct genl_info *info)
{
	return -EOPNOTSUPP;
}

int drbd_nl_resource_opts_doit(struct sk_buff *skb, struct genl_info *info)
{
	return -EOPNOTSUPP;
}

int drbd_nl_connect_doit(struct sk_buff *skb, struct genl_info *info)
{
	return -EOPNOTSUPP;
}

int drbd_nl_disconnect_doit(struct sk_buff *skb, struct genl_info *info)
{
	return -EOPNOTSUPP;
}

int drbd_nl_attach_doit(struct sk_buff *skb, struct genl_info *info)
{
	return -EOPNOTSUPP;
}

int drbd_nl_resize_doit(struct sk_buff *skb, struct genl_info *info)
{
	return -EOPNOTSUPP;
}

int drbd_nl_primary_doit(struct sk_buff *skb, struct genl_info *info)
{
	return -EOPNOTSUPP;
}

int drbd_nl_secondary_doit(struct sk_buff *skb, struct genl_info *info)
{
	return -EOPNOTSUPP;
}

int drbd_nl_new_c_uuid_doit(struct sk_buff *skb, struct genl_info *info)
{
	return -EOPNOTSUPP;
}

int drbd_nl_start_ov_doit(struct sk_buff *skb, struct genl_info *info)
{
	return -EOPNOTSUPP;
}

int drbd_nl_detach_doit(struct sk_buff *skb, struct genl_info *info)
{
	return -EOPNOTSUPP;
}

int drbd_nl_invalidate_doit(struct sk_buff *skb, struct genl_info *info)
{
	return -EOPNOTSUPP;
}

int drbd_nl_inval_peer_doit(struct sk_buff *skb, struct genl_info *info)
{
	return -EOPNOTSUPP;
}

int drbd_nl_pause_sync_doit(struct sk_buff *skb, struct genl_info *info)
{
	return -EOPNOTSUPP;
}

int drbd_nl_resume_sync_doit(struct sk_buff *skb, struct genl_info *info)
{
	return -EOPNOTSUPP;
}

int drbd_nl_suspend_io_doit(struct sk_buff *skb, struct genl_info *info)
{
	return -EOPNOTSUPP;
}

int drbd_nl_resume_io_doit(struct sk_buff *skb, struct genl_info *info)
{
	return -EOPNOTSUPP;
}

int drbd_nl_outdate_doit(struct sk_buff *skb, struct genl_info *info)
{
	return -EOPNOTSUPP;
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
	return -EOPNOTSUPP;
}

int drbd_nl_chg_disk_opts_doit(struct sk_buff *skb, struct genl_info *info)
{
	return -EOPNOTSUPP;
}

int drbd_nl_chg_net_opts_doit(struct sk_buff *skb, struct genl_info *info)
{
	return -EOPNOTSUPP;
}

int drbd_nl_get_resources_dumpit(struct sk_buff *skb, struct netlink_callback *cb)
{
	return -EOPNOTSUPP;
}

int drbd_nl_get_devices_dumpit(struct sk_buff *skb, struct netlink_callback *cb)
{
	return -EOPNOTSUPP;
}

int drbd_nl_get_connections_dumpit(struct sk_buff *skb, struct netlink_callback *cb)
{
	return -EOPNOTSUPP;
}

int drbd_nl_get_peer_devices_dumpit(struct sk_buff *skb, struct netlink_callback *cb)
{
	return -EOPNOTSUPP;
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
