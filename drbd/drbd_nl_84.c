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

	/*
	 * Some v1 attributes arrive nested under a DRBD_NLA_* container
	 * whose overlay() call hands out a "dst" of a different type than
	 * the DRBD 9 struct that attribute's value actually belongs to
	 * (DRBD 9 split or relocated these options into structs of their
	 * own). compat84_overlay() stashes them here while parsing the
	 * container that actually carries them on the wire; the handler that
	 * implements the command owning their real struct applies them
	 * from here. Every stashed field carries its own "has_*" flag, set
	 * only when that specific field's own attribute was present in the
	 * request, not merely the enclosing container: each of these
	 * fields is independently optional on the wire (a disk-options or
	 * net-options call can legitimately touch just one sibling and
	 * leave the rest unsent), so a single container-level flag would
	 * misreport the unsent siblings as "sent as zero". A handler must
	 * check a field's own flag before applying it, exactly as
	 * overlay() itself only ever changes the attributes a request
	 * actually sent.
	 */

	/* the v1 disk_conf's six resync-tuning fields -> struct drbd_peer_device_conf
	 * (an exact six-for-six match by field name); parsed while
	 * overlaying DRBD_NL_SET_DISK_CONF. Applied later in this series.
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

	/* v1 disk_conf.fencing -> drbd_net_conf.fencing_policy; parsed while
	 * overlaying DRBD_NL_SET_DISK_CONF. Applied later in this series.
	 */
	bool has_fencing_policy_84;
	u32 fencing_policy_84;

	/* v1 net_conf.{discard_my_data, tentative} -> struct drbd_connect_parms
	 * (an exact two-for-two match); parsed while overlaying
	 * DRBD_NL_SET_NET_CONF. Applied later in this series.
	 */
	struct {
		bool has_discard_my_data;
		unsigned char discard_my_data;
		bool has_tentative;
		unsigned char tentative;
	} connect_parms_84;
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
 * untouched" contract. The one-shot action parms start from a zeroed
 * dst, so a zeroed local struct already matches.
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
	case DRBD_NL_SET_PEER_DEVICE_CONF:
	case DRBD_NL_SET_DEVICE_CONF:
	case DRBD_NL_SET_INVALIDATE_PARMS:
	case DRBD_NL_SET_INVALIDATE_PEER_PARMS:
	case DRBD_NL_SET_FORGET_PEER_PARMS:
	case DRBD_NL_SET_CONNECT_PARMS:
	case DRBD_NL_SET_PATH_PARMS:
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
