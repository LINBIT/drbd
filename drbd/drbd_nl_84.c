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
#include "drbd-84/drbd_nl_gen.h"

static const struct genl_multicast_group drbd_nl_mcgrps[] = {
	[DRBD_NLGRP_EVENTS] = { .name = "events", },
};

static struct genl_family drbd_nl_family __ro_after_init = {
	.name		= DRBD_FAMILY_NAME,
	.version	= DRBD_FAMILY_VERSION,
	.hdrsize	= NLA_ALIGN(sizeof(struct drbd_genlmsghdr)),
	.split_ops	= drbd_nl_ops,
	.n_split_ops	= ARRAY_SIZE(drbd_nl_ops),
	.mcgrps		= drbd_nl_mcgrps,
	.n_mcgrps	= ARRAY_SIZE(drbd_nl_mcgrps),
	.module		= THIS_MODULE,
};

int drbd_pre_doit(const struct genl_split_ops *ops, struct sk_buff *skb,
		  struct genl_info *info)
{
	return -EOPNOTSUPP;
}

void drbd_post_doit(const struct genl_split_ops *ops, struct sk_buff *skb,
		    struct genl_info *info)
{
}

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
	return -EOPNOTSUPP;
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
	return genl_register_family(&drbd_nl_family);
}

void drbd_nl_legacy_exit(void)
{
	genl_unregister_family(&drbd_nl_family);
}
