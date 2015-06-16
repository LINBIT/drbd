/*
   drbd_nl.c

   This file is part of DRBD by Philipp Reisner and Lars Ellenberg.

   Copyright (C) 2001-2008, LINBIT Information Technologies GmbH.
   Copyright (C) 1999-2008, Philipp Reisner <philipp.reisner@linbit.com>.
   Copyright (C) 2002-2008, Lars Ellenberg <lars.ellenberg@linbit.com>.

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

#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/drbd.h>
#include <linux/in.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/blkpg.h>
#include <linux/cpumask.h>
#include <linux/random.h>
#include "drbd_int.h"
#include "drbd_protocol.h"
#include "drbd_req.h"
#include "drbd_state_change.h"
#include "drbd_debugfs.h"
#include "drbd_transport.h"
#include <asm/unaligned.h>
#include <linux/drbd_limits.h>
#include <linux/kthread.h>
#include <linux/security.h>
#include <net/genetlink.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,31)
/*
 * copied from more recent kernel source
 */
int genl_register_family_with_ops(struct genl_family *family,
	struct genl_ops *ops, size_t n_ops)
{
	int err, i;

	err = genl_register_family(family);
	if (err)
		return err;

	for (i = 0; i < n_ops; ++i, ++ops) {
		err = genl_register_ops(family, ops);
		if (err)
			goto err_out;
	}
	return 0;
err_out:
	genl_unregister_family(family);
	return err;
}
#endif

/* .doit */
// int drbd_adm_create_resource(struct sk_buff *skb, struct genl_info *info);
// int drbd_adm_delete_resource(struct sk_buff *skb, struct genl_info *info);

int drbd_adm_new_minor(struct sk_buff *skb, struct genl_info *info);
int drbd_adm_del_minor(struct sk_buff *skb, struct genl_info *info);

int drbd_adm_new_resource(struct sk_buff *skb, struct genl_info *info);
int drbd_adm_del_resource(struct sk_buff *skb, struct genl_info *info);
int drbd_adm_down(struct sk_buff *skb, struct genl_info *info);

int drbd_adm_set_role(struct sk_buff *skb, struct genl_info *info);
int drbd_adm_attach(struct sk_buff *skb, struct genl_info *info);
int drbd_adm_disk_opts(struct sk_buff *skb, struct genl_info *info);
int drbd_adm_detach(struct sk_buff *skb, struct genl_info *info);
int drbd_adm_connect(struct sk_buff *skb, struct genl_info *info);
int drbd_adm_new_peer(struct sk_buff *skb, struct genl_info *info);
int drbd_adm_del_peer(struct sk_buff *skb, struct genl_info *info);
int drbd_adm_new_path(struct sk_buff *skb, struct genl_info *info);
int drbd_adm_del_path(struct sk_buff *skb, struct genl_info *info);
int drbd_adm_net_opts(struct sk_buff *skb, struct genl_info *info);
int drbd_adm_peer_device_opts(struct sk_buff *skb, struct genl_info *info);
int drbd_adm_resize(struct sk_buff *skb, struct genl_info *info);
int drbd_adm_start_ov(struct sk_buff *skb, struct genl_info *info);
int drbd_adm_new_c_uuid(struct sk_buff *skb, struct genl_info *info);
int drbd_adm_disconnect(struct sk_buff *skb, struct genl_info *info);
int drbd_adm_invalidate(struct sk_buff *skb, struct genl_info *info);
int drbd_adm_invalidate_peer(struct sk_buff *skb, struct genl_info *info);
int drbd_adm_pause_sync(struct sk_buff *skb, struct genl_info *info);
int drbd_adm_resume_sync(struct sk_buff *skb, struct genl_info *info);
int drbd_adm_suspend_io(struct sk_buff *skb, struct genl_info *info);
int drbd_adm_resume_io(struct sk_buff *skb, struct genl_info *info);
int drbd_adm_outdate(struct sk_buff *skb, struct genl_info *info);
int drbd_adm_resource_opts(struct sk_buff *skb, struct genl_info *info);
int drbd_adm_get_status(struct sk_buff *skb, struct genl_info *info);
int drbd_adm_get_timeout_type(struct sk_buff *skb, struct genl_info *info);
int drbd_adm_forget_peer(struct sk_buff *skb, struct genl_info *info);
/* .dumpit */
int drbd_adm_dump_resources(struct sk_buff *skb, struct netlink_callback *cb);
int drbd_adm_dump_devices(struct sk_buff *skb, struct netlink_callback *cb);
int drbd_adm_dump_devices_done(struct netlink_callback *cb);
int drbd_adm_dump_connections(struct sk_buff *skb, struct netlink_callback *cb);
int drbd_adm_dump_connections_done(struct netlink_callback *cb);
int drbd_adm_dump_peer_devices(struct sk_buff *skb, struct netlink_callback *cb);
int drbd_adm_dump_peer_devices_done(struct netlink_callback *cb);
int drbd_adm_get_initial_state(struct sk_buff *skb, struct netlink_callback *cb);

#include <linux/drbd_genl_api.h>
#include "drbd_nla.h"
#include <linux/genl_magic_func.h>

atomic_t drbd_genl_seq = ATOMIC_INIT(2); /* two. */

DEFINE_MUTEX(notification_mutex);

/* used blkdev_get_by_path, to claim our meta data device(s) */
static char *drbd_m_holder = "Hands off! this is DRBD's meta data device.";

static void drbd_adm_send_reply(struct sk_buff *skb, struct genl_info *info)
{
	genlmsg_end(skb, genlmsg_data(nlmsg_data(nlmsg_hdr(skb))));
	if (genlmsg_reply(skb, info))
		pr_err("error sending genl reply\n");
}

/* Used on a fresh "drbd_adm_prepare"d reply_skb, this cannot fail: The only
 * reason it could fail was no space in skb, and there are 4k available. */
static int drbd_msg_put_info(struct sk_buff *skb, const char *info)
{
	struct nlattr *nla;
	int err = -EMSGSIZE;

	if (!info || !info[0])
		return 0;

	nla = nla_nest_start(skb, DRBD_NLA_CFG_REPLY);
	if (!nla)
		return err;

	err = nla_put_string(skb, T_info_text, info);
	if (err) {
		nla_nest_cancel(skb, nla);
		return err;
	} else
		nla_nest_end(skb, nla);
	return 0;
}

static int drbd_adm_finish(struct drbd_config_context *, struct genl_info *, int);

extern struct genl_ops drbd_genl_ops[];

#ifdef COMPAT_HAVE_SECURITY_NETLINK_RECV
#define drbd_security_netlink_recv(skb, cap) \
	security_netlink_recv(skb, cap)
#else
/* see
 * fd77846 security: remove the security_netlink_recv hook as it is equivalent to capable()
 */
static inline bool drbd_security_netlink_recv(struct sk_buff *skb, int cap)
{
	return !capable(cap);
}
#endif


static struct drbd_path *first_path(struct drbd_connection *connection)
{
	/* Ideally this function is removed at a later point in time.
	   It was introduced when replacing the single address pair
	   with a list of address pairs (or paths). */

	return list_first_entry_or_null(&connection->transport.paths, struct drbd_path, list);
}

/* This would be a good candidate for a "pre_doit" hook,
 * and per-family private info->pointers.
 * But we need to stay compatible with older kernels.
 * If it returns successfully, adm_ctx members are valid.
 *
 * At this point, we still rely on the global genl_lock().
 * If we want to avoid that, and allow "genl_family.parallel_ops", we may need
 * to add additional synchronization against object destruction/modification.
 */
#define DRBD_ADM_NEED_MINOR        (1 << 0)
#define DRBD_ADM_NEED_RESOURCE     (1 << 1)
#define DRBD_ADM_NEED_CONNECTION   (1 << 2)
#define DRBD_ADM_NEED_PEER_DEVICE  (1 << 3)
#define DRBD_ADM_NEED_PEER_NODE    (1 << 4)
#define DRBD_ADM_IGNORE_VERSION    (1 << 5)
static int drbd_adm_prepare(struct drbd_config_context *adm_ctx,
	struct sk_buff *skb, struct genl_info *info, unsigned flags)
{
	struct drbd_genlmsghdr *d_in = info->userhdr;
	const u8 cmd = info->genlhdr->cmd;
	int err;

	memset(adm_ctx, 0, sizeof(*adm_ctx));

	/*
	 * genl_rcv_msg() only checks if commands with the GENL_ADMIN_PERM flag
	 * set have CAP_NET_ADMIN; we also require CAP_SYS_ADMIN for
	 * administrative commands.
	 */
	if ((drbd_genl_ops[cmd].flags & GENL_ADMIN_PERM) &&
	    drbd_security_netlink_recv(skb, CAP_SYS_ADMIN))
		return -EPERM;

	adm_ctx->reply_skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!adm_ctx->reply_skb) {
		err = -ENOMEM;
		goto fail;
	}

	adm_ctx->reply_dh = genlmsg_put_reply(adm_ctx->reply_skb,
					info, &drbd_genl_family, 0, cmd);
	/* put of a few bytes into a fresh skb of >= 4k will always succeed.
	 * but anyways */
	if (!adm_ctx->reply_dh) {
		err = -ENOMEM;
		goto fail;
	}

	if (info->genlhdr->version != GENL_MAGIC_VERSION && (flags & DRBD_ADM_IGNORE_VERSION) == 0) {
		drbd_msg_put_info(adm_ctx->reply_skb, "Wrong API version, upgrade your drbd utils.");
		err = -EINVAL;
		goto fail;
	}

	if (flags & DRBD_ADM_NEED_PEER_DEVICE)
		flags |= DRBD_ADM_NEED_CONNECTION;
	if (flags & DRBD_ADM_NEED_CONNECTION)
		flags |= DRBD_ADM_NEED_PEER_NODE;
	if (flags & DRBD_ADM_NEED_PEER_NODE)
		flags |= DRBD_ADM_NEED_RESOURCE;

	adm_ctx->reply_dh->minor = d_in->minor;
	adm_ctx->reply_dh->ret_code = NO_ERROR;

	adm_ctx->volume = VOLUME_UNSPECIFIED;
	adm_ctx->peer_node_id = PEER_NODE_ID_UNSPECIFIED;
	if (info->attrs[DRBD_NLA_CFG_CONTEXT]) {
		struct nlattr *nla;
		/* parse and validate only */
		err = drbd_cfg_context_from_attrs(NULL, info);
		if (err)
			goto fail;

		/* It was present, and valid,
		 * copy it over to the reply skb. */
		err = nla_put_nohdr(adm_ctx->reply_skb,
				info->attrs[DRBD_NLA_CFG_CONTEXT]->nla_len,
				info->attrs[DRBD_NLA_CFG_CONTEXT]);
		if (err)
			goto fail;

		/* and assign stuff to the adm_ctx */
		nla = nested_attr_tb[__nla_type(T_ctx_volume)];
		if (nla)
			adm_ctx->volume = nla_get_u32(nla);
		nla = nested_attr_tb[__nla_type(T_ctx_peer_node_id)];
		if (nla)
			adm_ctx->peer_node_id = nla_get_u32(nla);
		nla = nested_attr_tb[__nla_type(T_ctx_resource_name)];
		if (nla)
			adm_ctx->resource_name = nla_data(nla);
	}

	if (adm_ctx->resource_name) {
		adm_ctx->resource = drbd_find_resource(adm_ctx->resource_name);
		if (adm_ctx->resource)
			kref_debug_get(&adm_ctx->resource->kref_debug, 2);
	}

	adm_ctx->minor = d_in->minor;
	adm_ctx->device = minor_to_device(d_in->minor);
	if (!adm_ctx->device && (flags & DRBD_ADM_NEED_MINOR)) {
		drbd_msg_put_info(adm_ctx->reply_skb, "unknown minor");
		err = ERR_MINOR_INVALID;
		goto finish;
	}
	if (!adm_ctx->resource && (flags & DRBD_ADM_NEED_RESOURCE)) {
		drbd_msg_put_info(adm_ctx->reply_skb, "unknown resource");
		err = ERR_INVALID_REQUEST;
		if (adm_ctx->resource_name)
			err = ERR_RES_NOT_KNOWN;
		goto finish;
	}
	if (adm_ctx->peer_node_id != PEER_NODE_ID_UNSPECIFIED) {
		/* peer_node_id is unsigned int */
		if (adm_ctx->peer_node_id >= DRBD_NODE_ID_MAX) {
			drbd_msg_put_info(adm_ctx->reply_skb, "peer node id out of range");
			err = ERR_INVALID_REQUEST;
			goto finish;
		}
		if (adm_ctx->peer_node_id == adm_ctx->resource->res_opts.node_id) {
			drbd_msg_put_info(adm_ctx->reply_skb, "peer node id cannot be my own node id");
			err = ERR_INVALID_REQUEST;
			goto finish;
		}
		adm_ctx->connection = drbd_get_connection_by_node_id(adm_ctx->resource, adm_ctx->peer_node_id);
		if (adm_ctx->connection)
			kref_debug_get(&adm_ctx->connection->kref_debug, 2);
	} else if (flags & DRBD_ADM_NEED_PEER_NODE) {
		drbd_msg_put_info(adm_ctx->reply_skb, "peer node id missing");
		err = ERR_INVALID_REQUEST;
		goto finish;
	}
	if (flags & DRBD_ADM_NEED_CONNECTION) {
		if (!adm_ctx->connection) {
			drbd_msg_put_info(adm_ctx->reply_skb, "unknown connection");
			err = ERR_INVALID_REQUEST;
			goto finish;
		}
	}
	if (flags & DRBD_ADM_NEED_PEER_DEVICE) {
		if (adm_ctx->volume != VOLUME_UNSPECIFIED)
			adm_ctx->peer_device =
				idr_find(&adm_ctx->connection->peer_devices,
					 adm_ctx->volume);
		if (!adm_ctx->peer_device) {
			drbd_msg_put_info(adm_ctx->reply_skb, "unknown volume");
			err = ERR_INVALID_REQUEST;
			goto finish;
		}
		if (!adm_ctx->device)
			adm_ctx->device = adm_ctx->peer_device->device;
	}
	if (adm_ctx->device) {
		kref_get(&adm_ctx->device->kref);
		kref_debug_get(&adm_ctx->device->kref_debug, 4);
	}

	/* some more paranoia, if the request was over-determined */
	if (adm_ctx->device && adm_ctx->resource &&
	    adm_ctx->device->resource != adm_ctx->resource) {
		pr_warning("request: minor=%u, resource=%s; but that minor belongs to resource %s\n",
				adm_ctx->minor, adm_ctx->resource->name,
				adm_ctx->device->resource->name);
		drbd_msg_put_info(adm_ctx->reply_skb, "minor exists in different resource");
		err = ERR_INVALID_REQUEST;
		goto finish;
	}
	if (adm_ctx->device &&
	    adm_ctx->volume != VOLUME_UNSPECIFIED &&
	    adm_ctx->volume != adm_ctx->device->vnr) {
		pr_warning("request: minor=%u, volume=%u; but that minor is volume %u in %s\n",
				adm_ctx->minor, adm_ctx->volume,
				adm_ctx->device->vnr,
				adm_ctx->device->resource->name);
		drbd_msg_put_info(adm_ctx->reply_skb, "minor exists as different volume");
		err = ERR_INVALID_REQUEST;
		goto finish;
	}
	if (adm_ctx->peer_device &&
	    adm_ctx->peer_device->device != adm_ctx->device) {
		drbd_msg_put_info(adm_ctx->reply_skb, "peer_device->device != device");
		pr_warning("request: minor=%u, resource=%s, volume=%u, peer_node=%u; device != peer_device->device\n",
				adm_ctx->minor, adm_ctx->resource->name,
				adm_ctx->device->vnr, adm_ctx->peer_node_id);
		err = ERR_INVALID_REQUEST;
		goto finish;
	}

	/* still, provide adm_ctx->resource always, if possible. */
	if (!adm_ctx->resource) {
		adm_ctx->resource = adm_ctx->device ? adm_ctx->device->resource
			: adm_ctx->connection ? adm_ctx->connection->resource : NULL;
		if (adm_ctx->resource) {
			kref_get(&adm_ctx->resource->kref);
			kref_debug_get(&adm_ctx->resource->kref_debug, 2);
		}
	}
	return NO_ERROR;

fail:
	nlmsg_free(adm_ctx->reply_skb);
	adm_ctx->reply_skb = NULL;
	return err;

finish:
	return drbd_adm_finish(adm_ctx, info, err);
}

static int drbd_adm_finish(struct drbd_config_context *adm_ctx, struct genl_info *info, int retcode)
{
	if (adm_ctx->device) {
		kref_debug_put(&adm_ctx->device->kref_debug, 4);
		kref_put(&adm_ctx->device->kref, drbd_destroy_device);
		adm_ctx->device = NULL;
	}
	if (adm_ctx->connection) {
		kref_debug_put(&adm_ctx->connection->kref_debug, 2);
		kref_put(&adm_ctx->connection->kref, drbd_destroy_connection);
		adm_ctx->connection = NULL;
	}
	if (adm_ctx->resource) {
		kref_debug_put(&adm_ctx->resource->kref_debug, 2);
		kref_put(&adm_ctx->resource->kref, drbd_destroy_resource);
		adm_ctx->resource = NULL;
	}

	if (!adm_ctx->reply_skb)
		return -ENOMEM;

	adm_ctx->reply_dh->ret_code = retcode;
	drbd_adm_send_reply(adm_ctx->reply_skb, info);
	adm_ctx->reply_skb = NULL;
	return 0;
}

static void conn_md_sync(struct drbd_connection *connection)
{
	struct drbd_peer_device *peer_device;
	int vnr;

	rcu_read_lock();
	idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
		struct drbd_device *device = peer_device->device;
		kref_get(&device->kref);
		rcu_read_unlock();
		drbd_md_sync(device);
		kref_put(&device->kref, drbd_destroy_device);
		rcu_read_lock();
	}
	rcu_read_unlock();
}

/* Buffer to construct the environment of a user-space helper in. */
struct env {
	char *buffer;
	int size, pos;
};

/* Print into an env buffer. */
static __printf(2, 3) int env_print(struct env *env, const char *fmt, ...)
{
	va_list args;
	int pos, ret;

	pos = env->pos;
	if (pos < 0)
		return pos;
	va_start(args, fmt);
	ret = vsnprintf(env->buffer + pos, env->size - pos, fmt, args);
	va_end(args);
	if (ret < 0) {
		env->pos = ret;
		goto out;
	}
	if (ret >= env->size - pos) {
		ret = env->pos = -ENOMEM;
		goto out;
	}
	env->pos += ret + 1;
    out:
	return ret;
}

/* Put env variables for an address into an env buffer. */
static void env_print_address(struct env *env, const char *prefix,
			      struct sockaddr_storage *storage)
{
	const char *afs;

	switch (storage->ss_family) {
	case AF_INET6:
		afs = "ipv6";
		env_print(env, "%sADDRESS=%pI6", prefix,
			  &((struct sockaddr_in6 *)storage)->sin6_addr);
		break;
	case AF_INET:
		afs = "ipv4";
		env_print(env, "%sADDRESS=%pI4", prefix,
			  &((struct sockaddr_in *)storage)->sin_addr);
		break;
	default:
		afs = "ssocks";
		env_print(env, "%sADDRESS=%pI4", prefix,
			  &((struct sockaddr_in *)storage)->sin_addr);
	}
	env_print(env, "%sAF=%s", prefix, afs);
}

/* Construct char **envp inside an env buffer. */
static char **make_envp(struct env *env)
{
	char **envp, *b;
	unsigned int n;

	if (env->pos < 0)
		return NULL;
	if (env->pos >= env->size)
		goto out_nomem;
	env->buffer[env->pos++] = 0;
	for (b = env->buffer, n = 1; *b; n++)
		b = strchr(b, 0) + 1;
	if (env->size - env->pos < sizeof(envp) * n)
		goto out_nomem;
	envp = (char **)(env->buffer + env->size) - n;

	for (b = env->buffer; *b; ) {
		*envp++ = b;
		b = strchr(b, 0) + 1;
	}
	*envp++ = NULL;
	return envp - n;

    out_nomem:
	env->pos = -ENOMEM;
	return NULL;
}

/* Macro refers to local variables peer_device, device and connection! */
#define magic_printk(level, fmt, args...)				\
	if (peer_device)						\
		__drbd_printk_peer_device(level, peer_device, fmt, args); \
	else if (device)						\
		__drbd_printk_device(level, device, fmt, args);		\
	else								\
		__drbd_printk_connection(level, connection, fmt, args);

int drbd_khelper(struct drbd_device *device, struct drbd_connection *connection, char *cmd)
{
	struct drbd_resource *resource = device ? device->resource : connection->resource;
	char *argv[] = {usermode_helper, cmd, resource->name, NULL };
	struct drbd_peer_device *peer_device = NULL;
	struct env env = { .size = PAGE_SIZE };
	char **envp;
	int ret;

    enlarge_buffer:
	env.buffer = (char *)__get_free_pages(GFP_NOIO, get_order(env.size));
	if (!env.buffer) {
		ret = -ENOMEM;
		goto out_err;
	}
	env.pos = 0;

	rcu_read_lock();
	env_print(&env, "HOME=/");
	env_print(&env, "TERM=linux");
	env_print(&env, "PATH=/sbin:/usr/sbin:/bin:/usr/bin");
	if (device) {
		env_print(&env, "DRBD_MINOR=%u", device_to_minor(device));
		env_print(&env, "DRBD_VOLUME=%u", device->vnr);
		if (get_ldev(device)) {
			struct disk_conf *disk_conf =
				rcu_dereference(device->ldev->disk_conf);
			env_print(&env, "DRBD_BACKING_DEV=%s",
				  disk_conf->backing_dev);
			put_ldev(device);
		}
	}
	if (connection) {
		struct drbd_path *path = first_path(connection);
		if (path) {
			/* TO BE DELETED */
			env_print_address(&env, "DRBD_MY_", &path->my_addr);
			env_print_address(&env, "DRBD_PEER_", &path->peer_addr);
		}
		env_print(&env, "DRBD_PEER_NODE_ID=%u", connection->peer_node_id);
	}
	if (connection && !device) {
		struct drbd_peer_device *peer_device;
		int vnr;

		idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
			struct drbd_device *device = peer_device->device;

			env_print(&env, "DRBD_MINOR_%u=%u",
				  vnr, peer_device->device->minor);
			if (get_ldev(device)) {
				struct disk_conf *disk_conf =
					rcu_dereference(device->ldev->disk_conf);
				env_print(&env, "DRBD_BACKING_DEV_%u=%s",
					  vnr, disk_conf->backing_dev);
				put_ldev(device);
			}
		}
	}
	rcu_read_unlock();

	envp = make_envp(&env);
	if (!envp) {
		if (env.pos == -ENOMEM) {
			free_pages((unsigned long)env.buffer, get_order(env.size));
			env.size += PAGE_SIZE;
			goto enlarge_buffer;
		}
		ret = env.pos;
		goto out_err;
	}

	if (current == resource->worker.task)
		set_bit(CALLBACK_PENDING, &resource->flags);

	/* The helper may take some time.
	 * write out any unsynced meta data changes now */
	if (device)
		drbd_md_sync(device);
	else if (connection)
		conn_md_sync(connection);

	if (connection && device)
		peer_device = conn_peer_device(connection, device->vnr);

	magic_printk(KERN_INFO, "helper command: %s %s\n", usermode_helper, cmd);
	notify_helper(NOTIFY_CALL, device, connection, cmd, 0);
	ret = call_usermodehelper(usermode_helper, argv, envp, UMH_WAIT_PROC);
	magic_printk(ret ? KERN_WARNING : KERN_INFO,
		     "helper command: %s %s exit code %u (0x%x)\n",
		     usermode_helper, cmd,
		     (ret >> 8) & 0xff, ret);
	notify_helper(NOTIFY_RESPONSE, device, connection, cmd, ret);

	if (current == resource->worker.task)
		clear_bit(CALLBACK_PENDING, &resource->flags);

	if (ret < 0) /* Ignore any ERRNOs we got. */
		ret = 0;

	free_pages((unsigned long)env.buffer, get_order(env.size));
	return ret;

    out_err:
	drbd_err(resource, "Could not call %s user-space helper: error %d"
		 "out of memory\n", cmd, ret);
	return 0;
}

#undef magic_printk

static bool initial_states_pending(struct drbd_connection *connection)
{
	struct drbd_peer_device *peer_device;
	int vnr;
	bool pending = false;

	rcu_read_lock();
	idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
		if (test_bit(INITIAL_STATE_SENT, &peer_device->flags) &&
		    !test_bit(INITIAL_STATE_RECEIVED, &peer_device->flags)) {
			pending = true;
			break;
		}
	}
	rcu_read_unlock();
	return pending;
}

bool conn_try_outdate_peer(struct drbd_connection *connection)
{
	unsigned long last_reconnect_jif;
	enum drbd_fencing_policy fencing_policy;
	char *ex_to_string;
	int r;
	unsigned long irq_flags;

	spin_lock_irq(&connection->resource->req_lock);
	if (connection->cstate[NOW] >= C_CONNECTED) {
		drbd_err(connection, "Expected cstate < C_CONNECTED\n");
		spin_unlock_irq(&connection->resource->req_lock);
		return false;
	}

	last_reconnect_jif = connection->last_reconnect_jif;
	spin_unlock_irq(&connection->resource->req_lock);

	fencing_policy = connection->fencing_policy;
	if (fencing_policy == FP_DONT_CARE)
		return true;

	r = drbd_khelper(NULL, connection, "fence-peer");

	begin_state_change(connection->resource, &irq_flags, CS_VERBOSE);
	switch ((r>>8) & 0xff) {
	case 3: /* peer is inconsistent */
		ex_to_string = "peer is inconsistent or worse";
		__change_peer_disk_states(connection, D_INCONSISTENT);
		break;
	case 4: /* peer got outdated, or was already outdated */
		ex_to_string = "peer was fenced";
		__change_peer_disk_states(connection, D_OUTDATED);
		break;
	case 5: /* peer was down */
		if (conn_highest_disk(connection) == D_UP_TO_DATE) {
			/* we will(have) create(d) a new UUID anyways... */
			ex_to_string = "peer is unreachable, assumed to be dead";
			__change_peer_disk_states(connection, D_OUTDATED);
		} else {
			ex_to_string = "peer unreachable, doing nothing since disk != UpToDate";
		}
		break;
	case 6: /* Peer is primary, voluntarily outdate myself.
		 * This is useful when an unconnected R_SECONDARY is asked to
		 * become R_PRIMARY, but finds the other peer being active. */
		ex_to_string = "peer is active";
		drbd_warn(connection, "Peer is primary, outdating myself.\n");
		__change_disk_states(connection->resource, D_OUTDATED);
		break;
	case 7:
		/* THINK: do we need to handle this
		 * like case 4, or more like case 5? */
		if (fencing_policy != FP_STONITH)
			drbd_err(connection, "fence-peer() = 7 && fencing != Stonith !!!\n");
		ex_to_string = "peer was stonithed";
		__change_peer_disk_states(connection, D_OUTDATED);
		break;
	default:
		/* The script is broken ... */
		drbd_err(connection, "fence-peer helper broken, returned %d\n", (r>>8)&0xff);
		abort_state_change(connection->resource, &irq_flags);
		return false; /* Eventually leave IO frozen */
	}

	drbd_info(connection, "fence-peer helper returned %d (%s)\n",
		  (r>>8) & 0xff, ex_to_string);

	if (connection->cstate[NOW] >= C_CONNECTED ||
	    initial_states_pending(connection)) {
		/* connection re-established; do not fence */
		goto abort;
	}
	if (connection->last_reconnect_jif != last_reconnect_jif) {
		/* In case the connection was established and dropped
		   while the fence-peer handler was running, ignore it */
		drbd_info(connection, "Ignoring fence-peer exit code\n");
		goto abort;
	}

	end_state_change(connection->resource, &irq_flags);

	goto out;
 abort:
	abort_state_change(connection->resource, &irq_flags);
 out:
	return conn_highest_pdsk(connection) <= D_OUTDATED;
}

static int _try_outdate_peer_async(void *data)
{
	struct drbd_connection *connection = (struct drbd_connection *)data;

	conn_try_outdate_peer(connection);

	kref_debug_put(&connection->kref_debug, 4);
	kref_put(&connection->kref, drbd_destroy_connection);
	return 0;
}

void conn_try_outdate_peer_async(struct drbd_connection *connection)
{
	struct task_struct *opa;

	kref_get(&connection->kref);
	kref_debug_get(&connection->kref_debug, 4);
	/* We may just have force_sig()'ed this thread
	 * to get it out of some blocking network function.
	 * Clear signals; otherwise kthread_run(), which internally uses
	 * wait_on_completion_killable(), will mistake our pending signal
	 * for a new fatal signal and fail. */
	flush_signals(current);
	opa = kthread_run(_try_outdate_peer_async, connection, "drbd_async_h");
	if (IS_ERR(opa)) {
		drbd_err(connection, "out of mem, failed to invoke fence-peer helper\n");
		kref_debug_put(&connection->kref_debug, 4);
		kref_put(&connection->kref, drbd_destroy_connection);
	}
}

static bool barrier_pending(struct drbd_resource *resource)
{
	struct drbd_connection *connection;
	bool rv = false;

	rcu_read_lock();
	for_each_connection_rcu(connection, resource) {
		if (test_bit(BARRIER_ACK_PENDING, &connection->flags)) {
			rv = true;
			break;
		}
	}
	rcu_read_unlock();

	return rv;
}

enum drbd_state_rv
drbd_set_role(struct drbd_resource *resource, enum drbd_role role, bool force)
{
	struct drbd_device *device;
	int vnr;
	const int max_tries = 4;
	enum drbd_state_rv rv = SS_UNKNOWN_ERROR;
	int try = 0;
	int forced = 0;
	bool with_force = false;


retry:
	down(&resource->state_sem);

	if (role == R_PRIMARY) {
		struct drbd_connection *connection;

		/* Detect dead peers as soon as possible.  */

		rcu_read_lock();
		for_each_connection_rcu(connection, resource)
			request_ping(connection);
		rcu_read_unlock();
	} else /* (role == R_SECONDARY) */ {
		if (start_new_tl_epoch(resource)) {
			struct drbd_connection *connection;
			u64 im;

			for_each_connection_ref(connection, im, resource)
				drbd_flush_workqueue(&connection->sender_work);
		}
		wait_event(resource->barrier_wait, !barrier_pending(resource));
		/* In case switching from R_PRIMARY to R_SECONDARY works
		   out, there is no rw opener at this point. Thus, no new
		   writes can come in. -> Flushing queued peer acks is
		   necessary and sufficient.
		   The cluster wide role change required packets to be
		   received by the aserder. -> We can be sure that the
		   peer_acks queued on asender's TODO list go out before
		   we send the two phase commit packet.
		*/
		drbd_flush_peer_acks(resource);
	}

	while (try++ < max_tries) {
		rv = stable_state_change(resource,
			change_role(resource, role,
				    CS_ALREADY_SERIALIZED | CS_DONT_RETRY | CS_WAIT_COMPLETE,
				    with_force));

		if (rv == SS_CONCURRENT_ST_CHG)
			continue;

		if (rv == SS_TIMEOUT) {
			long timeout = twopc_retry_timeout(resource, try);
			/* It might be that the receiver tries to start resync, and
			   sleeps on state_sem. Give it up, and retry in a short
			   while */
			up(&resource->state_sem);
			schedule_timeout_interruptible(timeout);
			goto retry;
		}
		/* in case we first succeeded to outdate,
		 * but now suddenly could establish a connection */
		if (rv == SS_CW_FAILED_BY_PEER) {
			with_force = false;
			continue;
		}

		if (rv == SS_NO_UP_TO_DATE_DISK && force && !with_force) {
			with_force = true;
			forced = 1;
			continue;
		}

		if (rv == SS_NO_UP_TO_DATE_DISK && !with_force) {
			struct drbd_connection *connection;
			u64 im;

			for_each_connection_ref(connection, im, resource) {
				struct drbd_peer_device *peer_device;
				int vnr;

				if (conn_highest_pdsk(connection) != D_UNKNOWN)
					continue;

				idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
					struct drbd_device *device = peer_device->device;

					if (device->disk_state[NOW] != D_CONSISTENT)
						continue;

					if (conn_try_outdate_peer(connection))
						with_force = true;
				}
			}
			if (with_force)
				continue;
		}

		if (rv == SS_NOTHING_TO_DO)
			goto out;
		if (rv == SS_PRIMARY_NOP && !with_force) {
			struct drbd_connection *connection;
			u64 im;

			for_each_connection_ref(connection, im, resource) {
				if (!conn_try_outdate_peer(connection) && force) {
					drbd_warn(connection, "Forced into split brain situation!\n");
					with_force = true;
				}
			}
			if (with_force)
				continue;
		}

		if (rv == SS_TWO_PRIMARIES) {
			struct drbd_connection *connection;
			struct net_conf *nc;
			int timeout = 0;

			/*
			 * Catch the case where we discover that the other
			 * primary has died soon after the state change
			 * failure: retry once after a short timeout.
			 */

			rcu_read_lock();
			for_each_connection_rcu(connection, resource) {
				nc = rcu_dereference(connection->transport.net_conf);
				if (nc && nc->ping_timeo > timeout)
					timeout = nc->ping_timeo;
			}
			rcu_read_unlock();
			timeout = timeout * HZ / 10;
			if (timeout == 0)
				timeout = 1;

			schedule_timeout_interruptible(timeout);
			if (try < max_tries)
				try = max_tries - 1;
			continue;
		}

		if (rv < SS_SUCCESS) {
			rv = stable_state_change(resource,
				change_role(resource, role,
					    CS_VERBOSE | CS_ALREADY_SERIALIZED |
					    CS_DONT_RETRY | CS_WAIT_COMPLETE,
					    with_force));
			if (rv < SS_SUCCESS)
				goto out;
		}
		break;
	}

	if (rv < SS_SUCCESS)
		goto out;

	if (forced)
		drbd_warn(resource, "Forced to consider local data as UpToDate!\n");

	if (role == R_SECONDARY) {
		idr_for_each_entry(&resource->devices, device, vnr) {
			if (get_ldev(device)) {
				device->ldev->md.current_uuid &= ~UUID_PRIMARY;
				put_ldev(device);
			}
		}
	} else {
		struct drbd_connection *connection;

		mutex_lock(&resource->conf_update);
		for_each_connection(connection, resource)
			clear_bit(CONN_DISCARD_MY_DATA, &connection->flags);
		mutex_unlock(&resource->conf_update);

		idr_for_each_entry(&resource->devices, device, vnr) {
			if (forced)
				drbd_uuid_new_current(device, true);
			else
				set_bit(NEW_CUR_UUID, &device->flags);
		}
	}

	idr_for_each_entry(&resource->devices, device, vnr) {
		 struct drbd_peer_device *peer_device;
		 u64 im;

		 for_each_peer_device_ref(peer_device, im, device) {
			/* writeout of activity log covered areas of the bitmap
			 * to stable storage done in after state change already */

			if (peer_device->connection->cstate[NOW] == C_CONNECTED) {
				/* if this was forced, we should consider sync */
				if (forced) {
					drbd_send_uuids(peer_device, 0, 0);
					set_bit(CONSIDER_RESYNC, &peer_device->flags);
				}
				drbd_send_current_state(peer_device);
			}
		}
	}

	idr_for_each_entry(&resource->devices, device, vnr) {
		drbd_md_sync(device);
		set_disk_ro(device->vdisk, role == R_SECONDARY);
		if (!resource->res_opts.auto_promote && role == R_PRIMARY)
			drbd_kobject_uevent(device);
	}

out:
	up(&resource->state_sem);
	return rv;
}

static const char *from_attrs_err_to_txt(int err)
{
	return	err == -ENOMSG ? "required attribute missing" :
		err == -EOPNOTSUPP ? "unknown mandatory attribute" :
		err == -EEXIST ? "can not change invariant setting" :
		"invalid attribute value";
}

int drbd_adm_set_role(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_config_context adm_ctx;
	struct set_role_parms parms;
	int err;
	enum drbd_state_rv retcode;

	retcode = drbd_adm_prepare(&adm_ctx, skb, info, DRBD_ADM_NEED_RESOURCE);
	if (!adm_ctx.reply_skb)
		return retcode;

	memset(&parms, 0, sizeof(parms));
	if (info->attrs[DRBD_NLA_SET_ROLE_PARMS]) {
		err = set_role_parms_from_attrs(&parms, info);
		if (err) {
			retcode = ERR_MANDATORY_TAG;
			drbd_msg_put_info(adm_ctx.reply_skb, from_attrs_err_to_txt(err));
			goto out;
		}
	}
	genl_unlock();
	mutex_lock(&adm_ctx.resource->adm_mutex);

	if (info->genlhdr->cmd == DRBD_ADM_PRIMARY) {
		retcode = drbd_set_role(adm_ctx.resource, R_PRIMARY, parms.assume_uptodate);
		if (retcode >= SS_SUCCESS)
			set_bit(EXPLICIT_PRIMARY, &adm_ctx.resource->flags);
	} else {
		retcode = drbd_set_role(adm_ctx.resource, R_SECONDARY, false);
		if (retcode >= SS_SUCCESS)
			clear_bit(EXPLICIT_PRIMARY, &adm_ctx.resource->flags);
	}

	mutex_unlock(&adm_ctx.resource->adm_mutex);
	genl_lock();
out:
	drbd_adm_finish(&adm_ctx, info, (enum drbd_ret_code)retcode);
	return 0;
}

u64 drbd_capacity_to_on_disk_bm_sect(u64 capacity_sect, unsigned int max_peers)
{
	u64 bits, bytes;

	/* round up storage sectors to full "bitmap sectors per bit", then
	 * convert to number of bits needed, and round that up to 64bit words
	 * to ease interoperability between 32bit and 64bit architectures.
	 */
	bits = ALIGN(BM_SECT_TO_BIT(ALIGN(capacity_sect, BM_SECT_PER_BIT)), 64);

	/* convert to bytes, multiply by number of peers,
	 * and, because we do all our meta data IO in 4k blocks,
	 * round up to full 4k
	 */
	bytes = ALIGN(bits / 8 * max_peers, 4096);

	/* convert to number of sectors */
	return bytes >> 9;
}

/* Initializes the md.*_offset members, so we are able to find
 * the on disk meta data.
 *
 * We currently have two possible layouts:
 * external:
 *   |----------- md_size_sect ------------------|
 *   [ 4k superblock ][ activity log ][  Bitmap  ]
 *   | al_offset == 8 |
 *   | bm_offset = al_offset + X      |
 *  ==> bitmap sectors = md_size_sect - bm_offset
 *
 * internal:
 *            |----------- md_size_sect ------------------|
 * [data.....][  Bitmap  ][ activity log ][ 4k superblock ]
 *                        | al_offset < 0 |
 *            | bm_offset = al_offset - Y |
 *  ==> bitmap sectors = Y = al_offset - bm_offset
 *
 *  Activity log size used to be fixed 32kB,
 *  but is about to become configurable.
 */
void drbd_md_set_sector_offsets(struct drbd_device *device,
				struct drbd_backing_dev *bdev)
{
	sector_t md_size_sect = 0;
	unsigned int al_size_sect = bdev->md.al_size_4k * 8;
	int max_peers;

	if (device->bitmap)
		max_peers = device->bitmap->bm_max_peers;
	else
		max_peers = 1;

	bdev->md.md_offset = drbd_md_ss(bdev);

	switch (bdev->md.meta_dev_idx) {
	default:
		/* v07 style fixed size indexed meta data */
		/* FIXME we should drop support for this! */
		bdev->md.md_size_sect = (128 << 20 >> 9);
		bdev->md.al_offset = (4096 >> 9);
		bdev->md.bm_offset = (4096 >> 9) + al_size_sect;
		break;
	case DRBD_MD_INDEX_FLEX_EXT:
		/* just occupy the full device; unit: sectors */
		bdev->md.md_size_sect = drbd_get_capacity(bdev->md_bdev);
		bdev->md.al_offset = (4096 >> 9);
		bdev->md.bm_offset = (4096 >> 9) + al_size_sect;
		break;
	case DRBD_MD_INDEX_INTERNAL:
	case DRBD_MD_INDEX_FLEX_INT:
		bdev->md.al_offset = -al_size_sect;

		/* enough bitmap to cover the storage,
		 * plus the "drbd meta data super block",
		 * and the activity log; */
		md_size_sect = drbd_capacity_to_on_disk_bm_sect(
				drbd_get_capacity(bdev->backing_bdev),
				max_peers)
			+ (4096 >> 9) + al_size_sect;

		bdev->md.md_size_sect = md_size_sect;
		/* bitmap offset is adjusted by 'super' block size */
		bdev->md.bm_offset   = -md_size_sect + (4096 >> 9);
		break;
	}
}

/* input size is expected to be in KB */
char *ppsize(char *buf, unsigned long long size)
{
	/* Needs 9 bytes at max including trailing NUL:
	 * -1ULL ==> "16384 EB" */
	static char units[] = { 'K', 'M', 'G', 'T', 'P', 'E' };
	int base = 0;
	while (size >= 10000 && base < sizeof(units)-1) {
		/* shift + round */
		size = (size >> 10) + !!(size & (1<<9));
		base++;
	}
	sprintf(buf, "%u %cB", (unsigned)size, units[base]);

	return buf;
}

/* The receiver may call drbd_suspend_io(device, WRITE_ONLY).
 * It should not call drbd_suspend_io(device, READ_AND_WRITE) since
 * if the node is an D_INCONSISTENT R_PRIMARY (L_SYNC_TARGET) it
 * may need to issue remote READs. Those is turn need the receiver
 * to complete. -> calling drbd_suspend_io(device, READ_AND_WRITE) deadlocks.
 */
/* Note these are not to be confused with
 * drbd_adm_suspend_io/drbd_adm_resume_io,
 * which are (sub) state changes triggered by admin (drbdsetup),
 * and can be long lived.
 * This changes an device->flag, is triggered by drbd internals,
 * and should be short-lived. */
/* It needs to be a counter, since multiple threads might
   independently suspend and resume IO. */
void drbd_suspend_io(struct drbd_device *device, enum suspend_scope ss)
{
	atomic_inc(&device->suspend_cnt);
	if (drbd_suspended(device))
		return;
	wait_event(device->misc_wait,
		   (atomic_read(&device->ap_bio_cnt[WRITE]) +
		    ss == READ_AND_WRITE ? atomic_read(&device->ap_bio_cnt[READ]) : 0) == 0);
}

void drbd_resume_io(struct drbd_device *device)
{
	if (atomic_dec_and_test(&device->suspend_cnt))
		wake_up(&device->misc_wait);
}

/**
 * effective_disk_size_determined()  -  is the effective disk size "fixed" already?
 *
 * When a device is configured in a cluster, the size of the replicated disk is
 * determined by the minimum size of the disks on all nodes.  Additional nodes
 * can be added, and this can still change the effective size of the replicated
 * disk.
 *
 * When the disk on any node becomes D_UP_TO_DATE, the effective disk size
 * becomes "fixed".  It is written to the metadata so that it will not be
 * forgotten across node restarts.  Further nodes can only be added if their
 * disks are big enough.
 */
static bool effective_disk_size_determined(struct drbd_device *device)
{
	struct drbd_peer_device *peer_device;
	bool rv = false;

	if (device->ldev->md.effective_size != 0)
		return true;
	if (device->disk_state[NEW] == D_UP_TO_DATE)
		return true;

	rcu_read_lock();
	for_each_peer_device_rcu(peer_device, device) {
		if (peer_device->disk_state[NEW] == D_UP_TO_DATE) {
			rv = true;
			break;
		}
	}
	rcu_read_unlock();

	return rv;
}

/**
 * drbd_determine_dev_size() -  Sets the right device size obeying all constraints
 * @device:	DRBD device.
 *
 * You should call drbd_md_sync() after calling this function.
 */
enum determine_dev_size
drbd_determine_dev_size(struct drbd_device *device, enum dds_flags flags, struct resize_parms *rs) __must_hold(local)
{
	sector_t prev_first_sect, prev_size; /* previous meta location */
	sector_t la_size, u_size;
	struct drbd_md *md = &device->ldev->md;
	u32 prev_al_stripe_size_4k;
	u32 prev_al_stripes;
	sector_t size;
	char ppb[10];
	void *buffer;

	int md_moved, la_size_changed;
	enum determine_dev_size rv = DS_UNCHANGED;

	/* race:
	 * application request passes inc_ap_bio,
	 * but then cannot get an AL-reference.
	 * this function later may wait on ap_bio_cnt == 0. -> deadlock.
	 *
	 * to avoid that:
	 * Suspend IO right here.
	 * still lock the act_log to not trigger ASSERTs there.
	 */
	drbd_suspend_io(device, READ_AND_WRITE);
	buffer = drbd_md_get_buffer(device, __func__); /* Lock meta-data IO */
	if (!buffer) {
		drbd_resume_io(device);
		return DS_ERROR;
	}

	/* no wait necessary anymore, actually we could assert that */
	wait_event(device->al_wait, lc_try_lock(device->act_log));

	prev_first_sect = drbd_md_first_sector(device->ldev);
	prev_size = device->ldev->md.md_size_sect;
	la_size = device->ldev->md.effective_size;

	if (rs) {
		/* rs is non NULL if we should change the AL layout only */

		prev_al_stripes = md->al_stripes;
		prev_al_stripe_size_4k = md->al_stripe_size_4k;

		md->al_stripes = rs->al_stripes;
		md->al_stripe_size_4k = rs->al_stripe_size / 4;
		md->al_size_4k = (u64)rs->al_stripes * rs->al_stripe_size / 4;
	}

	drbd_md_set_sector_offsets(device, device->ldev);

	rcu_read_lock();
	u_size = rcu_dereference(device->ldev->disk_conf)->disk_size;
	rcu_read_unlock();
	size = drbd_new_dev_size(device, u_size, flags & DDSF_FORCED);

	if (size < la_size) {
		if (rs && u_size == 0) {
			/* Remove "rs &&" later. This check should always be active, but
			   right now the receiver expects the permissive behavior */
			drbd_warn(device, "Implicit shrink not allowed. "
				 "Use --size=%llus for explicit shrink.\n",
				 (unsigned long long)size);
			rv = DS_ERROR_SHRINK;
		}
		if (u_size > size)
			rv = DS_ERROR_SPACE_MD;
		if (rv != DS_UNCHANGED)
			goto err_out;
	}

	if (drbd_get_capacity(device->this_bdev) != size ||
	    drbd_bm_capacity(device) != size) {
		int err;
		err = drbd_bm_resize(device, size, !(flags & DDSF_NO_RESYNC));
		if (unlikely(err)) {
			/* currently there is only one error: ENOMEM! */
			size = drbd_bm_capacity(device)>>1;
			if (size == 0) {
				drbd_err(device, "OUT OF MEMORY! "
				    "Could not allocate bitmap!\n");
			} else {
				drbd_err(device, "BM resizing failed. "
				    "Leaving size unchanged at size = %lu KB\n",
				    (unsigned long)size);
			}
			rv = DS_ERROR;
		}
		/* racy, see comments above. */
		drbd_set_my_capacity(device, size);
		if (effective_disk_size_determined(device)) {
			device->ldev->md.effective_size = size;
			drbd_info(device, "size = %s (%llu KB)\n", ppsize(ppb, size >> 1),
			     (unsigned long long)size >> 1);
		}
	}
	if (rv <= DS_ERROR)
		goto err_out;

	la_size_changed = (la_size != device->ldev->md.effective_size);

	md_moved = prev_first_sect != drbd_md_first_sector(device->ldev)
		|| prev_size	   != device->ldev->md.md_size_sect;

	if (la_size_changed || md_moved || rs) {
		u32 prev_flags;

		/* We do some synchronous IO below, which may take some time.
		 * Clear the timer, to avoid scary "timer expired!" messages,
		 * "Superblock" is written out at least twice below, anyways. */
		del_timer(&device->md_sync_timer);
		drbd_al_shrink(device); /* All extents inactive. */

		prev_flags = md->flags;
		md->flags &= ~MDF_PRIMARY_IND;
		drbd_md_write(device, buffer);

		drbd_info(device, "Writing the whole bitmap, %s\n",
			 la_size_changed && md_moved ? "size changed and md moved" :
			 la_size_changed ? "size changed" : "md moved");
		/* next line implicitly does drbd_suspend_io()+drbd_resume_io() */
		drbd_bitmap_io(device, md_moved ? &drbd_bm_write_all : &drbd_bm_write,
			       "size changed", BM_LOCK_ALL, NULL);
		drbd_initialize_al(device, buffer);

		md->flags = prev_flags;
		drbd_md_write(device, buffer);

		if (rs)
			drbd_info(device, "Changed AL layout to al-stripes = %d, al-stripe-size-kB = %d\n",
				 md->al_stripes, md->al_stripe_size_4k * 4);
	}

	if (size > la_size)
		rv = la_size ? DS_GREW : DS_GREW_FROM_ZERO;
	if (size < la_size)
		rv = DS_SHRUNK;

	if (0) {
	err_out:
		if (rs) {
			md->al_stripes = prev_al_stripes;
			md->al_stripe_size_4k = prev_al_stripe_size_4k;
			md->al_size_4k = (u64)prev_al_stripes * prev_al_stripe_size_4k;

			drbd_md_set_sector_offsets(device, device->ldev);
		}
	}
	lc_unlock(device->act_log);
	wake_up(&device->al_wait);
	drbd_md_put_buffer(device);
	drbd_resume_io(device);

	return rv;
}

/**
 * all_known_peer_devices_connected()
 *
 * Check if all peer devices that have bitmap slots assigned in the metadata
 * are connected.
 */
static bool all_known_peer_devices_connected(struct drbd_device *device) __must_hold(local)
{
	int node_id;
	bool all_known;

	all_known = true;
	rcu_read_lock();
	for (node_id = 0; node_id < DRBD_NODE_ID_MAX; node_id++) {
		struct drbd_peer_device *peer_device;

		if (device->ldev->md.peers[node_id].bitmap_index == -1 ||
		    !device->ldev->md.peers[node_id].bitmap_uuid)
			continue;
		peer_device = peer_device_by_node_id(device, node_id);
		if (peer_device && peer_device->repl_state[NOW] >= L_ESTABLISHED)
			continue;

		all_known = false;
		break;
	}
	rcu_read_unlock();
	return all_known;
}

sector_t
drbd_new_dev_size(struct drbd_device *device, sector_t u_size, int assume_peer_has_space) __must_hold(local)
{
	struct drbd_peer_device *peer_device;
	sector_t p_size = 0;
	sector_t la_size = device->ldev->md.effective_size; /* last agreed size */
	sector_t m_size; /* my size */
	sector_t size = 0;

	rcu_read_lock();
	for_each_peer_device_rcu(peer_device, device) {
		if (peer_device->repl_state[NOW] < L_ESTABLISHED)
			continue;
		p_size = min_not_zero(p_size, peer_device->max_size);
	}
	rcu_read_unlock();

	m_size = drbd_get_max_capacity(device->ldev);

	if (assume_peer_has_space && !all_known_peer_devices_connected(device)) {
		drbd_warn(device, "Resize while not connected was forced by the user!\n");
		p_size = m_size;
	}

	if (p_size && m_size) {
		size = min_t(sector_t, p_size, m_size);
	} else {
		if (la_size) {
			size = la_size;
			if (m_size && m_size < size)
				size = m_size;
			if (p_size && p_size < size)
				size = p_size;
		} else {
			if (m_size)
				size = m_size;
			if (p_size)
				size = p_size;
		}
	}

	if (size == 0)
		drbd_err(device, "Both nodes diskless!\n");

	if (u_size) {
		if (u_size > size)
			drbd_err(device, "Requested disk size is too big (%lu > %lu)\n",
			    (unsigned long)u_size>>1, (unsigned long)size>>1);
		else
			size = u_size;
	}

	return size;
}

/**
 * drbd_check_al_size() - Ensures that the AL is of the right size
 * @device:	DRBD device.
 *
 * Returns -EBUSY if current al lru is still used, -ENOMEM when allocation
 * failed, and 0 on success. You should call drbd_md_sync() after you called
 * this function.
 */
static int drbd_check_al_size(struct drbd_device *device, struct disk_conf *dc)
{
	struct lru_cache *n, *t;
	struct lc_element *e;
	unsigned int in_use;
	int i;

	if (device->act_log &&
	    device->act_log->nr_elements == dc->al_extents)
		return 0;

	in_use = 0;
	t = device->act_log;
	n = lc_create("act_log", drbd_al_ext_cache, AL_UPDATES_PER_TRANSACTION,
		dc->al_extents, sizeof(struct lc_element), 0);

	if (n == NULL) {
		drbd_err(device, "Cannot allocate act_log lru!\n");
		return -ENOMEM;
	}
	spin_lock_irq(&device->al_lock);
	if (t) {
		for (i = 0; i < t->nr_elements; i++) {
			e = lc_element_by_index(t, i);
			if (e->refcnt)
				drbd_err(device, "refcnt(%d)==%d\n",
				    e->lc_number, e->refcnt);
			in_use += e->refcnt;
		}
	}
	if (!in_use)
		device->act_log = n;
	spin_unlock_irq(&device->al_lock);
	if (in_use) {
		drbd_err(device, "Activity log still in use!\n");
		lc_destroy(n);
		return -EBUSY;
	} else {
		lc_destroy(t);
	}
	drbd_md_mark_dirty(device); /* we changed device->act_log->nr_elemens */
	return 0;
}

static u32 common_connection_features(struct drbd_resource *resource)
{
	struct drbd_connection *connection;
	u32 features = -1;

	rcu_read_lock();
	for_each_connection_rcu(connection, resource) {
		if (connection->cstate[NOW] < C_CONNECTED)
			continue;
		features &= connection->agreed_features;
	}
	rcu_read_unlock();

	return features;
}

static void drbd_setup_queue_param(struct drbd_device *device, struct drbd_backing_dev *bdev,
				   unsigned int max_bio_size)
{
	struct request_queue * const q = device->rq_queue;
	unsigned int max_hw_sectors = max_bio_size >> 9;
	struct request_queue *b = NULL;

	if (bdev) {
		b = bdev->backing_bdev->bd_disk->queue;

		max_hw_sectors = min(queue_max_hw_sectors(b), max_bio_size >> 9);

		blk_set_stacking_limits(&q->limits);
#ifdef REQ_WRITE_SAME
		blk_queue_max_write_same_sectors(q, 0);
#endif
	}

	blk_queue_logical_block_size(q, 512);
	blk_queue_max_hw_sectors(q, max_hw_sectors);
	/* This is the workaround for "bio would need to, but cannot, be split" */
	blk_queue_segment_boundary(q, PAGE_CACHE_SIZE-1);
	if (b) {
		struct request_queue * const b = device->ldev->backing_bdev->bd_disk->queue;
		u32 agreed_featurs = common_connection_features(device->resource);

		q->limits.max_discard_sectors = DRBD_MAX_DISCARD_SECTORS;

		if (blk_queue_discard(b) && (agreed_featurs & FF_TRIM)) {
			/* We don't care, stacking below should fix it for the local device.
			 * Whether or not it is a suitable granularity on the remote device
			 * is not our problem, really. If you care, you need to
			 * use devices with similar topology on all peers. */
			q->limits.discard_granularity = 512;

			queue_flag_set_unlocked(QUEUE_FLAG_DISCARD, q);
		} else {
			queue_flag_clear_unlocked(QUEUE_FLAG_DISCARD, q);
			q->limits.discard_granularity = 0;
		}

		blk_queue_stack_limits(q, b);

		if (q->backing_dev_info.ra_pages != b->backing_dev_info.ra_pages) {
			drbd_info(device, "Adjusting my ra_pages to backing device's (%lu -> %lu)\n",
				 q->backing_dev_info.ra_pages,
				 b->backing_dev_info.ra_pages);
			q->backing_dev_info.ra_pages = b->backing_dev_info.ra_pages;
		}
	}

	/* To avoid confusion, if this queue does not support discard, clear
	 * max_discard_sectors, which is what lsblk -D reports to the user.  */
	if (!blk_queue_discard(q)) {
		q->limits.max_discard_sectors = 0;
		q->limits.discard_granularity = 0;
	}
}

void drbd_reconsider_max_bio_size(struct drbd_device *device, struct drbd_backing_dev *bdev)
{
	unsigned int max_bio_size = device->device_conf.max_bio_size;
	struct drbd_peer_device *peer_device;

	if (bdev) {
		max_bio_size = min(max_bio_size,
			queue_max_hw_sectors(bdev->backing_bdev->bd_disk->queue) << 9);
	}

	spin_lock_irq(&device->resource->req_lock);
	for_each_peer_device(peer_device, device) {
		if (peer_device->repl_state[NOW] >= L_ESTABLISHED)
			max_bio_size = min(max_bio_size, peer_device->max_bio_size);
	}
	spin_unlock_irq(&device->resource->req_lock);

	drbd_setup_queue_param(device, bdev, max_bio_size);
}

/* Make sure IO is suspended before calling this function(). */
static void drbd_try_suspend_al(struct drbd_device *device)
{
	struct drbd_peer_device *peer_device;
	bool suspend = true;
	int max_peers = device->bitmap->bm_max_peers, bitmap_index;

	for (bitmap_index = 0; bitmap_index < max_peers; bitmap_index++) {
		if (_drbd_bm_total_weight(device, bitmap_index) !=
		    drbd_bm_bits(device))
			return;
	}

	if (!lc_try_lock(device->act_log)) {
		drbd_warn(device, "Failed to lock al in %s()", __func__);
		return;
	}

	drbd_al_shrink(device);
	spin_lock_irq(&device->resource->req_lock);
	for_each_peer_device(peer_device, device) {
		if (peer_device->repl_state[NOW] >= L_ESTABLISHED) {
			suspend = false;
			break;
		}
	}
	if (suspend)
		suspend = !test_and_set_bit(AL_SUSPENDED, &device->flags);
	spin_unlock_irq(&device->resource->req_lock);
	lc_unlock(device->act_log);

	if (suspend)
		drbd_info(device, "Suspended AL updates\n");
}


static bool should_set_defaults(struct genl_info *info)
{
	unsigned flags = ((struct drbd_genlmsghdr*)info->userhdr)->flags;
	return 0 != (flags & DRBD_GENL_F_SET_DEFAULTS);
}

static unsigned int drbd_al_extents_max(struct drbd_backing_dev *bdev)
{
	/* This is limited by 16 bit "slot" numbers,
	 * and by available on-disk context storage.
	 *
	 * Also (u16)~0 is special (denotes a "free" extent).
	 *
	 * One transaction occupies one 4kB on-disk block,
	 * we have n such blocks in the on disk ring buffer,
	 * the "current" transaction may fail (n-1),
	 * and there is 919 slot numbers context information per transaction.
	 *
	 * 72 transaction blocks amounts to more than 2**16 context slots,
	 * so cap there first.
	 */
	const unsigned int max_al_nr = DRBD_AL_EXTENTS_MAX;
	const unsigned int sufficient_on_disk =
		(max_al_nr + AL_CONTEXT_PER_TRANSACTION -1)
		/AL_CONTEXT_PER_TRANSACTION;

	unsigned int al_size_4k = bdev->md.al_size_4k;

	if (al_size_4k > sufficient_on_disk)
		return max_al_nr;

	return (al_size_4k - 1) * AL_CONTEXT_PER_TRANSACTION;
}

static bool write_ordering_changed(struct disk_conf *a, struct disk_conf *b)
{
	return	a->disk_barrier != b->disk_barrier ||
		a->disk_flushes != b->disk_flushes ||
		a->disk_drain != b->disk_drain;
}

int drbd_adm_disk_opts(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_config_context adm_ctx;
	enum drbd_ret_code retcode;
	struct drbd_device *device;
	struct drbd_resource *resource;
	struct disk_conf *new_disk_conf, *old_disk_conf;
	struct drbd_peer_device *peer_device;
	int err;

	retcode = drbd_adm_prepare(&adm_ctx, skb, info, DRBD_ADM_NEED_MINOR);
	if (!adm_ctx.reply_skb)
		return retcode;

	device = adm_ctx.device;
	resource = device->resource;
	mutex_lock(&adm_ctx.resource->adm_mutex);

	/* we also need a disk
	 * to change the options on */
	if (!get_ldev(device)) {
		retcode = ERR_NO_DISK;
		goto out;
	}

	new_disk_conf = kmalloc(sizeof(struct disk_conf), GFP_KERNEL);
	if (!new_disk_conf) {
		retcode = ERR_NOMEM;
		goto fail;
	}

	mutex_lock(&resource->conf_update);
	old_disk_conf = device->ldev->disk_conf;
	*new_disk_conf = *old_disk_conf;
	if (should_set_defaults(info))
		set_disk_conf_defaults(new_disk_conf);

	err = disk_conf_from_attrs_for_change(new_disk_conf, info);
	if (err && err != -ENOMSG) {
		retcode = ERR_MANDATORY_TAG;
		drbd_msg_put_info(adm_ctx.reply_skb, from_attrs_err_to_txt(err));
		goto fail_unlock;
	}

	if (new_disk_conf->al_extents < DRBD_AL_EXTENTS_MIN)
		new_disk_conf->al_extents = DRBD_AL_EXTENTS_MIN;
	if (new_disk_conf->al_extents > drbd_al_extents_max(device->ldev))
		new_disk_conf->al_extents = drbd_al_extents_max(device->ldev);

	drbd_suspend_io(device, READ_AND_WRITE);
	wait_event(device->al_wait, lc_try_lock(device->act_log));
	drbd_al_shrink(device);
	err = drbd_check_al_size(device, new_disk_conf);
	lc_unlock(device->act_log);
	wake_up(&device->al_wait);
	drbd_resume_io(device);

	if (err) {
		retcode = ERR_NOMEM;
		goto fail_unlock;
	}

	lock_all_resources();
	retcode = drbd_resync_after_valid(device, new_disk_conf->resync_after);
	if (retcode == NO_ERROR) {
		rcu_assign_pointer(device->ldev->disk_conf, new_disk_conf);
		drbd_resync_after_changed(device);
	}
	unlock_all_resources();

	if (retcode != NO_ERROR)
		goto fail_unlock;

	mutex_unlock(&resource->conf_update);

	if (new_disk_conf->al_updates)
		device->ldev->md.flags &= ~MDF_AL_DISABLED;
	else
		device->ldev->md.flags |= MDF_AL_DISABLED;

	if (new_disk_conf->md_flushes)
		clear_bit(MD_NO_BARRIER, &device->flags);
	else
		set_bit(MD_NO_BARRIER, &device->flags);

	if (write_ordering_changed(old_disk_conf, new_disk_conf))
		drbd_bump_write_ordering(device->resource, NULL, WO_BIO_BARRIER);

	drbd_md_sync(device);

	for_each_peer_device(peer_device, device) {
		if (peer_device->repl_state[NOW] >= L_ESTABLISHED)
			drbd_send_sync_param(peer_device);
	}

	synchronize_rcu();
	kfree(old_disk_conf);
	mod_timer(&device->request_timer, jiffies + HZ);
	goto success;

fail_unlock:
	mutex_unlock(&resource->conf_update);
 fail:
	kfree(new_disk_conf);
success:
	if (retcode != NO_ERROR)
		synchronize_rcu();
	put_ldev(device);
 out:
	mutex_unlock(&adm_ctx.resource->adm_mutex);
	drbd_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

static void mutex_unlock_cond(struct mutex *mutex, bool *have_mutex)
{
	if (*have_mutex) {
		mutex_unlock(mutex);
		*have_mutex = false;
	}
}

static void update_resource_dagtag(struct drbd_resource *resource, struct drbd_backing_dev *bdev)
{
	u64 dagtag = 0;
	int node_id;

	for (node_id = 0; node_id < DRBD_NODE_ID_MAX; node_id++) {
		struct drbd_peer_md *peer_md;
		if (bdev->md.node_id == node_id)
			continue;

		peer_md = &bdev->md.peers[node_id];

		if (peer_md->bitmap_uuid)
			dagtag = max(peer_md->bitmap_dagtag, dagtag);
	}
	if (dagtag > resource->dagtag_sector)
		resource->dagtag_sector = dagtag;
}

static int used_bitmap_slots(struct drbd_backing_dev *bdev)
{
	int node_id;
	int used = 0;

	for (node_id = 0; node_id < DRBD_NODE_ID_MAX; node_id++) {
		struct drbd_peer_md *peer_md = &bdev->md.peers[node_id];

		if (peer_md->bitmap_index != -1)
			used++;
	}

	return used;
}

static bool bitmap_index_vacant(struct drbd_backing_dev *bdev, int bitmap_index)
{
	int node_id;

	for (node_id = 0; node_id < DRBD_NODE_ID_MAX; node_id++) {
		struct drbd_peer_md *peer_md = &bdev->md.peers[node_id];

		if (peer_md->bitmap_index == bitmap_index)
			return false;
	}
	return true;
}

int drbd_adm_attach(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_config_context adm_ctx;
	struct drbd_device *device;
	struct drbd_resource *resource;
	int err;
	enum drbd_ret_code retcode;
	enum determine_dev_size dd;
	sector_t max_possible_sectors;
	sector_t min_md_device_sectors;
	struct drbd_backing_dev *nbc; /* new_backing_conf */
	struct disk_conf *new_disk_conf = NULL;
	struct block_device *bdev;
	enum drbd_state_rv rv;
	struct drbd_peer_device *peer_device;
	unsigned int slots_needed = 0;
	bool have_conf_update = false;

	retcode = drbd_adm_prepare(&adm_ctx, skb, info, DRBD_ADM_NEED_MINOR);
	if (!adm_ctx.reply_skb)
		return retcode;
	device = adm_ctx.device;
	resource = device->resource;
	mutex_lock(&resource->adm_mutex);

	/* allocation not in the IO path, drbdsetup context */
	nbc = kzalloc(sizeof(struct drbd_backing_dev), GFP_KERNEL);
	if (!nbc) {
		retcode = ERR_NOMEM;
		goto fail;
	}
	spin_lock_init(&nbc->md.uuid_lock);

	new_disk_conf = kzalloc(sizeof(struct disk_conf), GFP_KERNEL);
	if (!new_disk_conf) {
		retcode = ERR_NOMEM;
		goto fail;
	}
	nbc->disk_conf = new_disk_conf;

	set_disk_conf_defaults(new_disk_conf);
	err = disk_conf_from_attrs(new_disk_conf, info);
	if (err) {
		retcode = ERR_MANDATORY_TAG;
		drbd_msg_put_info(adm_ctx.reply_skb, from_attrs_err_to_txt(err));
		goto fail;
	}

	if (new_disk_conf->meta_dev_idx < DRBD_MD_INDEX_FLEX_INT) {
		retcode = ERR_MD_IDX_INVALID;
		goto fail;
	}

	lock_all_resources();
	retcode = drbd_resync_after_valid(device, new_disk_conf->resync_after);
	unlock_all_resources();
	if (retcode != NO_ERROR)
		goto fail;

	bdev = blkdev_get_by_path(new_disk_conf->backing_dev,
				  FMODE_READ | FMODE_WRITE | FMODE_EXCL, device);
	if (IS_ERR(bdev)) {
		drbd_err(device, "open(\"%s\") failed with %ld\n", new_disk_conf->backing_dev,
			PTR_ERR(bdev));
		retcode = ERR_OPEN_DISK;
		goto fail;
	}
	nbc->backing_bdev = bdev;

	/*
	 * meta_dev_idx >= 0: external fixed size, possibly multiple
	 * drbd sharing one meta device.  TODO in that case, paranoia
	 * check that [md_bdev, meta_dev_idx] is not yet used by some
	 * other drbd minor!  (if you use drbd.conf + drbdadm, that
	 * should check it for you already; but if you don't, or
	 * someone fooled it, we need to double check here)
	 */
	bdev = blkdev_get_by_path(new_disk_conf->meta_dev,
				  FMODE_READ | FMODE_WRITE | FMODE_EXCL,
				  (new_disk_conf->meta_dev_idx < 0) ?
				  (void *)device : (void *)drbd_m_holder);
	if (IS_ERR(bdev)) {
		drbd_err(device, "open(\"%s\") failed with %ld\n", new_disk_conf->meta_dev,
			PTR_ERR(bdev));
		retcode = ERR_OPEN_MD_DISK;
		goto fail;
	}
	nbc->md_bdev = bdev;

	if ((nbc->backing_bdev == nbc->md_bdev) !=
	    (new_disk_conf->meta_dev_idx == DRBD_MD_INDEX_INTERNAL ||
	     new_disk_conf->meta_dev_idx == DRBD_MD_INDEX_FLEX_INT)) {
		retcode = ERR_MD_IDX_INVALID;
		goto fail;
	}

	mutex_lock(&resource->conf_update);
	have_conf_update = true;

	/* if you want to reconfigure, please tear down first */
	if (device->disk_state[NOW] > D_DISKLESS) {
		retcode = ERR_DISK_CONFIGURED;
		goto fail;
	}
	/* It may just now have detached because of IO error.  Make sure
	 * drbd_ldev_destroy is done already, we may end up here very fast,
	 * e.g. if someone calls attach from the on-io-error handler,
	 * to realize a "hot spare" feature (not that I'd recommend that) */
	wait_event(device->misc_wait, !test_bit(GOING_DISKLESS, &device->flags));

	/* make sure there is no leftover from previous force-detach attempts */
	clear_bit(FORCE_DETACH, &device->flags);
	clear_bit(WAS_READ_ERROR, &device->flags);

	/* and no leftover from previously aborted resync or verify, either */
	for_each_peer_device(peer_device, device) {
		peer_device->rs_total = 0;
		peer_device->rs_failed = 0;
		atomic_set(&peer_device->rs_pending_cnt, 0);
	}

	if (!device->bitmap) {
		device->bitmap = drbd_bm_alloc();
		if (!device->bitmap) {
			retcode = ERR_NOMEM;
			goto fail;
		}
	}

	/* Read our meta data super block early.
	 * This also sets other on-disk offsets. */
	retcode = drbd_md_read(device, nbc);
	if (retcode != NO_ERROR)
		goto fail;

	if (new_disk_conf->al_extents < DRBD_AL_EXTENTS_MIN)
		new_disk_conf->al_extents = DRBD_AL_EXTENTS_MIN;
	if (new_disk_conf->al_extents > drbd_al_extents_max(nbc))
		new_disk_conf->al_extents = drbd_al_extents_max(nbc);

	if (drbd_get_max_capacity(nbc) < new_disk_conf->disk_size) {
		drbd_err(device, "max capacity %llu smaller than disk size %llu\n",
			(unsigned long long) drbd_get_max_capacity(nbc),
			(unsigned long long) new_disk_conf->disk_size);
		retcode = ERR_DISK_TOO_SMALL;
		goto fail;
	}

	if (new_disk_conf->meta_dev_idx < 0) {
		max_possible_sectors = DRBD_MAX_SECTORS_FLEX;
		/* at least one MB, otherwise it does not make sense */
		min_md_device_sectors = (2<<10);
	} else {
		max_possible_sectors = DRBD_MAX_SECTORS;
		min_md_device_sectors = (128 << 20 >> 9) * (new_disk_conf->meta_dev_idx + 1);
	}

	if (drbd_get_capacity(nbc->md_bdev) < min_md_device_sectors) {
		retcode = ERR_MD_DISK_TOO_SMALL;
		drbd_warn(device, "refusing attach: md-device too small, "
		     "at least %llu sectors needed for this meta-disk type\n",
		     (unsigned long long) min_md_device_sectors);
		goto fail;
	}

	/* Make sure the new disk is big enough
	 * (we may currently be R_PRIMARY with no local disk...) */
	if (drbd_get_max_capacity(nbc) <
	    drbd_get_capacity(device->this_bdev)) {
		retcode = ERR_DISK_TOO_SMALL;
		goto fail;
	}

	nbc->known_size = drbd_get_capacity(nbc->backing_bdev);

	if (nbc->known_size > max_possible_sectors) {
		drbd_warn(device, "==> truncating very big lower level device "
			"to currently maximum possible %llu sectors <==\n",
			(unsigned long long) max_possible_sectors);
		if (new_disk_conf->meta_dev_idx >= 0)
			drbd_warn(device, "==>> using internal or flexible "
				      "meta data may help <<==\n");
	}

	drbd_suspend_io(device, READ_AND_WRITE);
	wait_event(resource->barrier_wait, !barrier_pending(resource));
	for_each_peer_device(peer_device, device)
		wait_event(device->misc_wait,
			   (!atomic_read(&peer_device->ap_pending_cnt) ||
			    drbd_suspended(device)));
	/* and for other previously queued resource work */
	drbd_flush_workqueue(&resource->work);

	rv = stable_state_change(resource,
		change_disk_state(device, D_ATTACHING, CS_VERBOSE | CS_SERIALIZE));
	retcode = rv;  /* FIXME: Type mismatch. */
	if (rv >= SS_SUCCESS)
		update_resource_dagtag(resource, nbc);
	drbd_resume_io(device);
	if (rv < SS_SUCCESS)
		goto fail;

	if (!get_ldev_if_state(device, D_ATTACHING))
		goto force_diskless;

	drbd_info(device, "Maximum number of peer devices = %u\n",
		  device->bitmap->bm_max_peers);

	/* Make sure the local node id matches or is unassigned */
	if (nbc->md.node_id != -1 && nbc->md.node_id != resource->res_opts.node_id) {
		drbd_err(device, "Local node id %d differs from local "
			 "node id %d on device\n",
			 resource->res_opts.node_id,
			 nbc->md.node_id);
		retcode = ERR_INVALID_REQUEST;
		goto force_diskless_dec;
	}

	/* Make sure no bitmap slot has our own node id */
	if (nbc->md.peers[resource->res_opts.node_id].bitmap_index != -1) {
		drbd_err(device, "There is a bitmap for my own node id (%d)\n",
			 resource->res_opts.node_id);
		retcode = ERR_INVALID_REQUEST;
		goto force_diskless_dec;
	}

	/* Make sure we have a bitmap slot for each peer id */
	for_each_peer_device(peer_device, device) {
		struct drbd_connection *connection = peer_device->connection;
		int bitmap_index;

		bitmap_index = nbc->md.peers[connection->peer_node_id].bitmap_index;
		if (bitmap_index != -1)
			peer_device->bitmap_index = bitmap_index;
		else
			slots_needed++;
	}
	if (slots_needed) {
		int slots_available = device->bitmap->bm_max_peers - used_bitmap_slots(nbc);

		if (slots_needed > slots_available) {
			drbd_err(device, "Not enough free bitmap "
				 "slots (available=%d, needed=%d)\n",
				 slots_available,
				 slots_needed);
			retcode = ERR_INVALID_REQUEST;
			goto force_diskless_dec;
		}
		for_each_peer_device(peer_device, device) {
			struct drbd_connection *connection = peer_device->connection;
			int bitmap_index;

			if (peer_device->bitmap_index != -1)
				continue;

			for (bitmap_index = 0; bitmap_index < device->bitmap->bm_max_peers; bitmap_index++) {
				if (bitmap_index_vacant(nbc, bitmap_index)) {
					const int node_id = connection->peer_node_id;
					struct drbd_peer_md *peer_md = &nbc->md.peers[node_id];

					peer_md->bitmap_index = bitmap_index;
					peer_device->bitmap_index = bitmap_index;
					peer_md->flags &= ~MDF_NODE_EXISTS; /* it is a peer now */
					goto next_device;
				}
			}
			drbd_err(device, "Not enough free bitmap slots\n");
			retcode = ERR_INVALID_REQUEST;
			goto force_diskless_dec;
		next_device:
			/* nothing to do */;
		}
	}

	/* Assign the local node id (if not assigned already) */
	nbc->md.node_id = resource->res_opts.node_id;

	if (resource->role[NOW] == R_PRIMARY && device->exposed_data_uuid &&
	    (device->exposed_data_uuid & ~UUID_PRIMARY) !=
	    (nbc->md.current_uuid & ~UUID_PRIMARY)) {
		int data_present = false;
		for_each_peer_device(peer_device, device) {
			if (peer_device->disk_state[NOW] == D_UP_TO_DATE)
				data_present = true;
		}
		if (!data_present) {
			drbd_err(device, "Can only attach to data with current UUID=%016llX\n",
				 (unsigned long long)device->exposed_data_uuid);
			retcode = ERR_DATA_NOT_CURRENT;
			goto force_diskless_dec;
		}
	}

	/* Since we are diskless, fix the activity log first... */
	if (drbd_check_al_size(device, new_disk_conf)) {
		retcode = ERR_NOMEM;
		goto force_diskless_dec;
	}

	/* Point of no return reached.
	 * Devices and memory are no longer released by error cleanup below.
	 * now device takes over responsibility, and the state engine should
	 * clean it up somewhere.  */
	D_ASSERT(device, device->ldev == NULL);
	device->ldev = nbc;
	nbc = NULL;
	new_disk_conf = NULL;

	for_each_peer_device(peer_device, device) {
		err = drbd_attach_peer_device(peer_device);
		if (err) {
			retcode = ERR_NOMEM;
			goto force_diskless_dec;
		}
	}

	lock_all_resources();
	retcode = drbd_resync_after_valid(device, device->ldev->disk_conf->resync_after);
	if (retcode != NO_ERROR) {
		unlock_all_resources();
		goto force_diskless_dec;
	}

	/* Reset the "barriers don't work" bits here, then force meta data to
	 * be written, to ensure we determine if barriers are supported. */
	if (device->ldev->disk_conf->md_flushes)
		clear_bit(MD_NO_BARRIER, &device->flags);
	else
		set_bit(MD_NO_BARRIER, &device->flags);

	drbd_resync_after_changed(device);
	drbd_bump_write_ordering(resource, device->ldev, WO_BIO_BARRIER);
	unlock_all_resources();

	/* Prevent shrinking of consistent devices ! */
	if (drbd_md_test_flag(device->ldev, MDF_CONSISTENT) &&
	    drbd_new_dev_size(device, device->ldev->disk_conf->disk_size, 0) <
	    device->ldev->md.effective_size) {
		drbd_warn(device, "refusing to truncate a consistent device\n");
		retcode = ERR_DISK_TOO_SMALL;
		goto force_diskless_dec;
	}

	if (drbd_md_test_flag(device->ldev, MDF_CRASHED_PRIMARY))
		set_bit(CRASHED_PRIMARY, &device->flags);
	else
		clear_bit(CRASHED_PRIMARY, &device->flags);

	if (drbd_md_test_flag(device->ldev, MDF_PRIMARY_IND) &&
	    !(resource->role[NOW] == R_PRIMARY && resource->susp_nod[NOW]))
		set_bit(CRASHED_PRIMARY, &device->flags);

	device->read_cnt = 0;
	device->writ_cnt = 0;

	drbd_reconsider_max_bio_size(device, device->ldev);

	/* If I am currently not R_PRIMARY,
	 * but meta data primary indicator is set,
	 * I just now recover from a hard crash,
	 * and have been R_PRIMARY before that crash.
	 *
	 * Now, if I had no connection before that crash
	 * (have been degraded R_PRIMARY), chances are that
	 * I won't find my peer now either.
	 *
	 * In that case, and _only_ in that case,
	 * we use the degr-wfc-timeout instead of the default,
	 * so we can automatically recover from a crash of a
	 * degraded but active "cluster" after a certain timeout.
	 */
	for_each_peer_device(peer_device, device) {
		clear_bit(USE_DEGR_WFC_T, &peer_device->flags);
		if (resource->role[NOW] != R_PRIMARY &&
		    drbd_md_test_flag(device->ldev, MDF_PRIMARY_IND) &&
		    !drbd_md_test_peer_flag(peer_device, MDF_PEER_CONNECTED))
			set_bit(USE_DEGR_WFC_T, &peer_device->flags);
	}

	dd = drbd_determine_dev_size(device, 0, NULL);
	if (dd == DS_ERROR) {
		retcode = ERR_NOMEM_BITMAP;
		goto force_diskless_dec;
	} else if (dd == DS_GREW) {
		for_each_peer_device(peer_device, device)
			set_bit(RESYNC_AFTER_NEG, &peer_device->flags);
	}

	if (drbd_bitmap_io(device, &drbd_bm_read,
		"read from attaching", BM_LOCK_ALL,
		NULL)) {
		retcode = ERR_IO_MD_DISK;
		goto force_diskless_dec;
	}

	for_each_peer_device(peer_device, device) {
		if ((test_bit(CRASHED_PRIMARY, &device->flags) &&
		     drbd_md_test_flag(device->ldev, MDF_AL_DISABLED)) ||
		    drbd_md_test_peer_flag(peer_device, MDF_PEER_FULL_SYNC)) {
			drbd_info(peer_device, "Assuming that all blocks are out of sync "
				  "(aka FullSync)\n");
			if (drbd_bitmap_io(device, &drbd_bmio_set_n_write,
				"set_n_write from attaching", BM_LOCK_ALL,
				peer_device)) {
				retcode = ERR_IO_MD_DISK;
				goto force_diskless_dec;
			}
		}
	}

	drbd_try_suspend_al(device); /* IO is still suspended here... */

	rcu_read_lock();
	if (rcu_dereference(device->ldev->disk_conf)->al_updates)
		device->ldev->md.flags &= ~MDF_AL_DISABLED;
	else
		device->ldev->md.flags |= MDF_AL_DISABLED;
	rcu_read_unlock();

	/* change_disk_state uses disk_state_from_md(device); in case D_NEGOTIATING not
	   necessary, and falls back to a local state change */
	rv = stable_state_change(resource,
		change_disk_state(device, D_NEGOTIATING, CS_VERBOSE | CS_SERIALIZE));

	if (rv < SS_SUCCESS)
		goto force_diskless_dec;

	mod_timer(&device->request_timer, jiffies + HZ);

	if (resource->role[NOW] == R_PRIMARY)
		device->ldev->md.current_uuid |= UUID_PRIMARY;
	else
		device->ldev->md.current_uuid &= ~UUID_PRIMARY;

	drbd_md_mark_dirty(device);
	drbd_md_sync(device);

	drbd_kobject_uevent(device);
	put_ldev(device);
	mutex_unlock(&resource->conf_update);
	mutex_unlock(&resource->adm_mutex);
	drbd_adm_finish(&adm_ctx, info, retcode);
	return 0;

 force_diskless_dec:
	put_ldev(device);
 force_diskless:
	change_disk_state(device, D_DISKLESS, CS_HARD);
	drbd_md_sync(device);
 fail:
	mutex_unlock_cond(&resource->conf_update, &have_conf_update);
	drbd_free_ldev(nbc); /* frees also new_disk_conf */

	mutex_unlock(&resource->adm_mutex);
	drbd_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

static enum drbd_disk_state get_disk_state(struct drbd_device *device)
{
	struct drbd_resource *resource = device->resource;
	enum drbd_disk_state disk_state;

	spin_lock_irq(&resource->req_lock);
	disk_state = device->disk_state[NOW];
	spin_unlock_irq(&resource->req_lock);
	return disk_state;
}

static int adm_detach(struct drbd_device *device, int force)
{
	enum drbd_state_rv retcode;
	int ret;

	if (force) {
		set_bit(FORCE_DETACH, &device->flags);
		change_disk_state(device, D_DETACHING, CS_HARD);
		retcode = SS_SUCCESS;
		goto out;
	}

	drbd_suspend_io(device, READ_AND_WRITE); /* so no-one is stuck in drbd_al_begin_io */
	retcode = stable_state_change(device->resource,
		change_disk_state(device, D_DETACHING,
			CS_VERBOSE | CS_WAIT_COMPLETE | CS_SERIALIZE));
	/* D_DETACHING will transition to DISKLESS. */
	drbd_resume_io(device);
	ret = wait_event_interruptible(device->misc_wait,
			get_disk_state(device) != D_DETACHING);
	if (retcode >= SS_SUCCESS)
		drbd_cleanup_device(device);
	if (retcode == SS_IS_DISKLESS)
		retcode = SS_NOTHING_TO_DO;
	if (ret)
		retcode = ERR_INTR;
out:
	return retcode;
}

/* Detaching the disk is a process in multiple stages.  First we need to lock
 * out application IO, in-flight IO, IO stuck in drbd_al_begin_io.
 * Then we transition to D_DISKLESS, and wait for put_ldev() to return all
 * internal references as well.
 * Only then we have finally detached. */
int drbd_adm_detach(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_config_context adm_ctx;
	enum drbd_ret_code retcode;
	struct detach_parms parms = { };
	int err;

	retcode = drbd_adm_prepare(&adm_ctx, skb, info, DRBD_ADM_NEED_MINOR);
	if (!adm_ctx.reply_skb)
		return retcode;

	if (info->attrs[DRBD_NLA_DETACH_PARMS]) {
		err = detach_parms_from_attrs(&parms, info);
		if (err) {
			retcode = ERR_MANDATORY_TAG;
			drbd_msg_put_info(adm_ctx.reply_skb, from_attrs_err_to_txt(err));
			goto out;
		}
	}

	mutex_lock(&adm_ctx.resource->adm_mutex);
	retcode = adm_detach(adm_ctx.device, parms.force_detach);
	mutex_unlock(&adm_ctx.resource->adm_mutex);
out:
	drbd_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

static bool conn_resync_running(struct drbd_connection *connection)
{
	struct drbd_peer_device *peer_device;
	bool rv = false;
	int vnr;

	rcu_read_lock();
	idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
		if (peer_device->repl_state[NOW] == L_SYNC_SOURCE ||
		    peer_device->repl_state[NOW] == L_SYNC_TARGET ||
		    peer_device->repl_state[NOW] == L_PAUSED_SYNC_S ||
		    peer_device->repl_state[NOW] == L_PAUSED_SYNC_T) {
			rv = true;
			break;
		}
	}
	rcu_read_unlock();

	return rv;
}

static bool conn_ov_running(struct drbd_connection *connection)
{
	struct drbd_peer_device *peer_device;
	bool rv = false;
	int vnr;

	rcu_read_lock();
	idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
		if (peer_device->repl_state[NOW] == L_VERIFY_S ||
		    peer_device->repl_state[NOW] == L_VERIFY_T) {
			rv = true;
			break;
		}
	}
	rcu_read_unlock();

	return rv;
}

static enum drbd_ret_code
_check_net_options(struct drbd_connection *connection, struct net_conf *old_net_conf, struct net_conf *new_net_conf)
{
	if (old_net_conf && connection->cstate[NOW] == C_CONNECTED && connection->agreed_pro_version < 100) {
		if (new_net_conf->wire_protocol != old_net_conf->wire_protocol)
			return ERR_NEED_APV_100;

		if (new_net_conf->two_primaries != old_net_conf->two_primaries)
			return ERR_NEED_APV_100;

		if (!new_net_conf->integrity_alg != !old_net_conf->integrity_alg)
			return ERR_NEED_APV_100;

		if (strcmp(new_net_conf->integrity_alg, old_net_conf->integrity_alg))
			return ERR_NEED_APV_100;
	}

	if (!new_net_conf->two_primaries &&
	    connection->resource->role[NOW] == R_PRIMARY &&
	    connection->peer_role[NOW] == R_PRIMARY)
		return ERR_NEED_ALLOW_TWO_PRI;

	if (new_net_conf->two_primaries &&
	    (new_net_conf->wire_protocol != DRBD_PROT_C))
		return ERR_NOT_PROTO_C;

	if (new_net_conf->wire_protocol == DRBD_PROT_A &&
	    new_net_conf->fencing_policy == FP_STONITH)
		return ERR_STONITH_AND_PROT_A;

	if (new_net_conf->on_congestion != OC_BLOCK &&
	    new_net_conf->wire_protocol != DRBD_PROT_A)
		return ERR_CONG_NOT_PROTO_A;

	return NO_ERROR;
}

static enum drbd_ret_code
check_net_options(struct drbd_connection *connection, struct net_conf *new_net_conf)
{
	static enum drbd_ret_code rv;
	struct drbd_peer_device *peer_device;
	int i;

	rcu_read_lock();
	rv = _check_net_options(connection, rcu_dereference(connection->transport.net_conf), new_net_conf);
	rcu_read_unlock();

	/* connection->peer_devices protected by genl_lock() here */
	idr_for_each_entry(&connection->peer_devices, peer_device, i) {
		struct drbd_device *device = peer_device->device;
		if (!device->bitmap) {
			device->bitmap = drbd_bm_alloc();
			if (!device->bitmap)
				return ERR_NOMEM;
		}
	}

	return rv;
}

struct crypto {
	struct crypto_hash *verify_tfm;
	struct crypto_hash *csums_tfm;
	struct crypto_hash *cram_hmac_tfm;
	struct crypto_hash *integrity_tfm;
};

static int
alloc_hash(struct crypto_hash **tfm, char *tfm_name, int err_alg)
{
	if (!tfm_name[0])
		return NO_ERROR;

	*tfm = crypto_alloc_hash(tfm_name, 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(*tfm)) {
		*tfm = NULL;
		return err_alg;
	}

	return NO_ERROR;
}

static enum drbd_ret_code
alloc_crypto(struct crypto *crypto, struct net_conf *new_net_conf)
{
	char hmac_name[CRYPTO_MAX_ALG_NAME];
	enum drbd_ret_code rv;

	rv = alloc_hash(&crypto->csums_tfm, new_net_conf->csums_alg,
		       ERR_CSUMS_ALG);
	if (rv != NO_ERROR)
		return rv;
	rv = alloc_hash(&crypto->verify_tfm, new_net_conf->verify_alg,
		       ERR_VERIFY_ALG);
	if (rv != NO_ERROR)
		return rv;
	rv = alloc_hash(&crypto->integrity_tfm, new_net_conf->integrity_alg,
		       ERR_INTEGRITY_ALG);
	if (rv != NO_ERROR)
		return rv;
	if (new_net_conf->cram_hmac_alg[0] != 0) {
		snprintf(hmac_name, CRYPTO_MAX_ALG_NAME, "hmac(%s)",
			 new_net_conf->cram_hmac_alg);

		rv = alloc_hash(&crypto->cram_hmac_tfm, hmac_name,
			       ERR_AUTH_ALG);
	}

	return rv;
}

static void free_crypto(struct crypto *crypto)
{
	crypto_free_hash(crypto->cram_hmac_tfm);
	crypto_free_hash(crypto->integrity_tfm);
	crypto_free_hash(crypto->csums_tfm);
	crypto_free_hash(crypto->verify_tfm);
}

int drbd_adm_net_opts(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_config_context adm_ctx;
	enum drbd_ret_code retcode;
	struct drbd_connection *connection;
	struct net_conf *old_net_conf, *new_net_conf = NULL;
	int err;
	int ovr; /* online verify running */
	int rsr; /* re-sync running */
	struct crypto crypto = { };

	retcode = drbd_adm_prepare(&adm_ctx, skb, info, DRBD_ADM_NEED_CONNECTION);
	if (!adm_ctx.reply_skb)
		return retcode;

	connection = adm_ctx.connection;
	mutex_lock(&adm_ctx.resource->adm_mutex);

	new_net_conf = kzalloc(sizeof(struct net_conf), GFP_KERNEL);
	if (!new_net_conf) {
		retcode = ERR_NOMEM;
		goto out;
	}

	drbd_flush_workqueue(&connection->sender_work);

	mutex_lock(&connection->resource->conf_update);
	mutex_lock(&connection->mutex[DATA_STREAM]);
	old_net_conf = connection->transport.net_conf;

	if (!old_net_conf) {
		drbd_msg_put_info(adm_ctx.reply_skb, "net conf missing, try connect");
		retcode = ERR_INVALID_REQUEST;
		goto fail;
	}

	*new_net_conf = *old_net_conf;
	if (should_set_defaults(info))
		set_net_conf_defaults(new_net_conf);

	err = net_conf_from_attrs_for_change(new_net_conf, info);
	if (err && err != -ENOMSG) {
		retcode = ERR_MANDATORY_TAG;
		drbd_msg_put_info(adm_ctx.reply_skb, from_attrs_err_to_txt(err));
		goto fail;
	}

	retcode = check_net_options(connection, new_net_conf);
	if (retcode != NO_ERROR)
		goto fail;

	/* re-sync running */
	rsr = conn_resync_running(connection);
	if (rsr && strcmp(new_net_conf->csums_alg, old_net_conf->csums_alg)) {
		retcode = ERR_CSUMS_RESYNC_RUNNING;
		goto fail;
	}

	/* online verify running */
	ovr = conn_ov_running(connection);
	if (ovr && strcmp(new_net_conf->verify_alg, old_net_conf->verify_alg)) {
		retcode = ERR_VERIFY_RUNNING;
		goto fail;
	}

	retcode = alloc_crypto(&crypto, new_net_conf);
	if (retcode != NO_ERROR)
		goto fail;

	rcu_assign_pointer(connection->transport.net_conf, new_net_conf);
	connection->fencing_policy = new_net_conf->fencing_policy;

	if (!rsr) {
		crypto_free_hash(connection->csums_tfm);
		connection->csums_tfm = crypto.csums_tfm;
		crypto.csums_tfm = NULL;
	}
	if (!ovr) {
		crypto_free_hash(connection->verify_tfm);
		connection->verify_tfm = crypto.verify_tfm;
		crypto.verify_tfm = NULL;
	}

	crypto_free_hash(connection->integrity_tfm);
	connection->integrity_tfm = crypto.integrity_tfm;
	if (connection->cstate[NOW] >= C_CONNECTED && connection->agreed_pro_version >= 100)
		/* Do this without trying to take connection->data.mutex again.  */
		__drbd_send_protocol(connection, P_PROTOCOL_UPDATE);

	crypto_free_hash(connection->cram_hmac_tfm);
	connection->cram_hmac_tfm = crypto.cram_hmac_tfm;

	mutex_unlock(&connection->mutex[DATA_STREAM]);
	mutex_unlock(&connection->resource->conf_update);
	synchronize_rcu();
	kfree(old_net_conf);

	if (connection->cstate[NOW] >= C_CONNECTED) {
		struct drbd_peer_device *peer_device;
		int vnr;

		idr_for_each_entry(&connection->peer_devices, peer_device, vnr)
			drbd_send_sync_param(peer_device);
	}

	goto out;

 fail:
	mutex_unlock(&connection->mutex[DATA_STREAM]);
	mutex_unlock(&connection->resource->conf_update);
	free_crypto(&crypto);
	kfree(new_net_conf);
 out:
	mutex_unlock(&adm_ctx.resource->adm_mutex);
	drbd_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

static int adjust_resync_fifo(struct drbd_peer_device *peer_device,
			      struct peer_device_conf *conf,
			      struct fifo_buffer **pp_old_plan)
{
	struct fifo_buffer *old_plan, *new_plan = NULL;
	int fifo_size;

	fifo_size = (conf->c_plan_ahead * 10 * SLEEP_TIME) / HZ;

	old_plan = rcu_dereference_protected(peer_device->rs_plan_s,
			     lockdep_is_held(&peer_device->connection->resource->conf_update));
	if (!old_plan || fifo_size != old_plan->size) {
		new_plan = fifo_alloc(fifo_size);
		if (!new_plan) {
			drbd_err(peer_device, "kmalloc of fifo_buffer failed");
			return -ENOMEM;
		}
		rcu_assign_pointer(peer_device->rs_plan_s, new_plan);
		if (pp_old_plan)
			*pp_old_plan = old_plan;
	}

	return 0;
}

int drbd_adm_peer_device_opts(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_config_context adm_ctx;
	enum drbd_ret_code retcode;
	struct drbd_peer_device *peer_device;
	struct peer_device_conf *old_peer_device_conf, *new_peer_device_conf = NULL;
	struct fifo_buffer *old_plan = NULL;
	int err;

	retcode = drbd_adm_prepare(&adm_ctx, skb, info, DRBD_ADM_NEED_PEER_DEVICE);
	if (!adm_ctx.reply_skb)
		return retcode;

	peer_device = adm_ctx.peer_device;

	mutex_lock(&adm_ctx.resource->adm_mutex);
	mutex_lock(&adm_ctx.resource->conf_update);

	new_peer_device_conf = kzalloc(sizeof(struct peer_device_conf), GFP_KERNEL);
	if (!new_peer_device_conf)
		goto fail;

	old_peer_device_conf = peer_device->conf;
	*new_peer_device_conf = *old_peer_device_conf;
	if (should_set_defaults(info))
		set_peer_device_conf_defaults(new_peer_device_conf);

	err = peer_device_conf_from_attrs_for_change(new_peer_device_conf, info);
	if (err && err != -ENOMSG) {
		retcode = ERR_MANDATORY_TAG;
		drbd_msg_put_info(adm_ctx.reply_skb, from_attrs_err_to_txt(err));
		goto fail;
	}

	if (!expect(peer_device, new_peer_device_conf->resync_rate >= 1))
		new_peer_device_conf->resync_rate = 1;

	if (new_peer_device_conf->c_plan_ahead > DRBD_C_PLAN_AHEAD_MAX)
		new_peer_device_conf->c_plan_ahead = DRBD_C_PLAN_AHEAD_MAX;

	err = adjust_resync_fifo(peer_device, new_peer_device_conf, &old_plan);
	if (err)
		goto fail;

	rcu_assign_pointer(peer_device->conf, new_peer_device_conf);

	synchronize_rcu();
	kfree(old_peer_device_conf);
	kfree(old_plan);

	if (0) {
fail:
		retcode = ERR_NOMEM;
		kfree(new_peer_device_conf);
	}

	mutex_unlock(&adm_ctx.resource->conf_update);
	mutex_unlock(&adm_ctx.resource->adm_mutex);
	drbd_adm_finish(&adm_ctx, info, retcode);
	return 0;

}

int drbd_create_peer_device_default_config(struct drbd_peer_device *peer_device)
{
	struct peer_device_conf *conf;
	int err;

	conf = kzalloc(sizeof(*conf), GFP_KERNEL);
	if (!conf)
		return -ENOMEM;

	set_peer_device_conf_defaults(conf);
	err = adjust_resync_fifo(peer_device, conf, NULL);
	if (err)
		return err;

	peer_device->conf = conf;

	return 0;
}

static void connection_to_info(struct connection_info *info,
			       struct drbd_connection *connection)
{
	info->conn_connection_state = connection->cstate[NOW];
	info->conn_role = connection->peer_role[NOW];
}

static void peer_device_to_info(struct peer_device_info *info,
				struct drbd_peer_device *peer_device)
{
	info->peer_repl_state = peer_device->repl_state[NOW];
	info->peer_disk_state = peer_device->disk_state[NOW];
	info->peer_resync_susp_user = peer_device->resync_susp_user[NOW];
	info->peer_resync_susp_peer = peer_device->resync_susp_peer[NOW];
	info->peer_resync_susp_dependency = peer_device->resync_susp_dependency[NOW];
}

static bool is_resync_target_in_other_connection(struct drbd_peer_device *peer_device)
{
	struct drbd_device *device = peer_device->device;
	struct drbd_peer_device *p;

	for_each_peer_device(p, device) {
		if (p == peer_device)
			continue;

		if (p->repl_state[NEW] == L_SYNC_TARGET)
			return true;
	}

	return false;
}

static int adm_new_connection(struct drbd_connection **ret_conn,
		struct drbd_config_context *adm_ctx, struct genl_info *info)
{
	struct connection_info connection_info;
	enum drbd_notification_type flags;
	unsigned int peer_devices = 0;
	struct drbd_device *device;
	struct drbd_peer_device *peer_device;
	struct net_conf *old_net_conf, *new_net_conf = NULL;
	struct crypto crypto = { NULL, };
	struct drbd_connection *connection;
	enum drbd_ret_code retcode;
	int i, err;
	bool allocate_bitmap_slots = false;
	char *transport_name;
	struct drbd_transport_class *tr_class;

	*ret_conn = NULL;
	if (adm_ctx->connection) {
		drbd_err(adm_ctx->resource, "Connection for peer node id %d already exists\n",
			 adm_ctx->peer_node_id);
		return ERR_INVALID_REQUEST;
	}

	/* allocation not in the IO path, drbdsetup / netlink process context */
	new_net_conf = kzalloc(sizeof(*new_net_conf), GFP_KERNEL);
	if (!new_net_conf)
		return ERR_NOMEM;

	set_net_conf_defaults(new_net_conf);

	err = net_conf_from_attrs(new_net_conf, info);
	if (err) {
		retcode = ERR_MANDATORY_TAG;
		drbd_msg_put_info(adm_ctx->reply_skb, from_attrs_err_to_txt(err));
		goto fail;
	}

	transport_name = new_net_conf->transport_name[0] ? new_net_conf->transport_name : "tcp";
	tr_class = drbd_get_transport_class(transport_name);
	if (!tr_class) {
		retcode = ERR_CREATE_TRANSPORT;
		goto fail;
	}

	connection = drbd_create_connection(adm_ctx->resource, tr_class);
	if (!connection) {
		retcode = ERR_NOMEM;
		goto fail_put_transport;
	}
	connection->peer_node_id = adm_ctx->peer_node_id;
	/* transport class reference now owned by connection,
	 * prevent double cleanup. */
	tr_class = NULL;

	retcode = check_net_options(connection, new_net_conf);
	if (retcode != NO_ERROR)
		goto fail_free_connection;

	retcode = alloc_crypto(&crypto, new_net_conf);
	if (retcode != NO_ERROR)
		goto fail_free_connection;

	((char *)new_net_conf->shared_secret)[SHARED_SECRET_MAX-1] = 0;

	mutex_lock(&adm_ctx->resource->conf_update);
	idr_for_each_entry(&adm_ctx->resource->devices, device, i) {
		int id;

		retcode = ERR_NOMEM;
		peer_device = create_peer_device(device, connection);
		if (!peer_device)
			goto unlock_fail_free_connection;
		id = idr_alloc(&connection->peer_devices, peer_device,
			       device->vnr, device->vnr + 1, GFP_KERNEL);
		if (id < 0)
			goto unlock_fail_free_connection;
	}

	spin_lock_irq(&adm_ctx->resource->req_lock);
	list_add_tail_rcu(&connection->connections, &adm_ctx->resource->connections);
	idr_for_each_entry(&connection->peer_devices, peer_device, i) {
		struct drbd_device *device = peer_device->device;

		peer_device->resync_susp_other_c[NOW] =
			is_resync_target_in_other_connection(peer_device);
		list_add_rcu(&peer_device->peer_devices, &device->peer_devices);
		kref_get(&connection->kref);
		kref_debug_get(&connection->kref_debug, 3);
		kref_get(&device->kref);
		kref_debug_get(&device->kref_debug, 1);
		peer_devices++;
	}
	spin_unlock_irq(&adm_ctx->resource->req_lock);

	old_net_conf = connection->transport.net_conf;
	if (old_net_conf) {
		retcode = ERR_NET_CONFIGURED;
		goto unlock_fail_free_connection;
	}
	rcu_assign_pointer(connection->transport.net_conf, new_net_conf);
	connection->fencing_policy = new_net_conf->fencing_policy;

	connection->cram_hmac_tfm = crypto.cram_hmac_tfm;
	connection->integrity_tfm = crypto.integrity_tfm;
	connection->csums_tfm = crypto.csums_tfm;
	connection->verify_tfm = crypto.verify_tfm;

	/* transferred ownership. prevent double cleanup. */
	new_net_conf = NULL;
	memset(&crypto, 0, sizeof(crypto));

	idr_for_each_entry(&connection->peer_devices, peer_device, i)
		peer_device->node_id = connection->peer_node_id;

	if (connection->peer_node_id > adm_ctx->resource->max_node_id)
		adm_ctx->resource->max_node_id = connection->peer_node_id;

	/* Make sure we have a bitmap slot for this peer id on each device */
	idr_for_each_entry(&connection->peer_devices, peer_device, i) {
		unsigned int bitmap_index;

		device = peer_device->device;
		if (!get_ldev(device))
			continue;

		bitmap_index = device->ldev->md.peers[adm_ctx->peer_node_id].bitmap_index;
		if (bitmap_index != -1) {
			peer_device->bitmap_index = bitmap_index;
		} else {
			int slots_available;

			allocate_bitmap_slots = true;

			slots_available = device->bitmap->bm_max_peers - used_bitmap_slots(device->ldev);
			if (slots_available <= 0) {
				drbd_err(device, "Not enough free bitmap "
					 "slots (available=%d, needed=%d)\n",
					 slots_available, 1);
				put_ldev(device);
				retcode = ERR_INVALID_REQUEST;
				goto unlock_fail_free_connection;
			}
		}

		put_ldev(device);
	}
	if (allocate_bitmap_slots) {
		idr_for_each_entry(&connection->peer_devices, peer_device, i) {
			unsigned int bitmap_index;

			device = peer_device->device;
			if (!get_ldev(device))
				continue;
			if (peer_device->bitmap_index != -1)
				goto next_device_2;
			for (bitmap_index = 0; bitmap_index < device->bitmap->bm_max_peers; bitmap_index++) {
				if (bitmap_index_vacant(device->ldev, bitmap_index)) {
					const int node_id = adm_ctx->peer_node_id;
					struct drbd_peer_md *peer_md = &device->ldev->md.peers[node_id];

					peer_md->bitmap_index = bitmap_index;
					drbd_md_mark_dirty(device);
					peer_device->bitmap_index = bitmap_index;
					peer_md->flags &= ~MDF_NODE_EXISTS; /* it is a peer now */
					goto next_device_2;
				}
			}
			drbd_err(device, "Not enough free bitmap slots\n");
			put_ldev(device);
			retcode = ERR_INVALID_REQUEST;
			goto unlock_fail_free_connection;

		next_device_2:
			put_ldev(device);
		}
	}

	connection_to_info(&connection_info, connection);
	flags = (peer_devices--) ? NOTIFY_CONTINUES : 0;
	mutex_lock(&notification_mutex);
	notify_connection_state(NULL, 0, connection, &connection_info, NOTIFY_CREATE | flags);
	idr_for_each_entry(&connection->peer_devices, peer_device, i) {
		struct peer_device_info peer_device_info;

		peer_device_to_info(&peer_device_info, peer_device);
		flags = (peer_devices--) ? NOTIFY_CONTINUES : 0;
		notify_peer_device_state(NULL, 0, peer_device, &peer_device_info, NOTIFY_CREATE | flags);
	}
	mutex_unlock(&notification_mutex);

	idr_for_each_entry(&connection->peer_devices, peer_device, i) {
		if (get_ldev_if_state(peer_device->device, D_NEGOTIATING)) {
			err = drbd_attach_peer_device(peer_device);
			put_ldev(peer_device->device);
			if (err) {
				retcode = ERR_NOMEM;
				goto unlock_fail_free_connection;
			}
		}
		peer_device->send_cnt = 0;
		peer_device->recv_cnt = 0;
	}
	mutex_unlock(&adm_ctx->resource->conf_update);

	drbd_debugfs_connection_add(connection); /* after ->net_conf was assigned */
	drbd_thread_start(&connection->sender);
	*ret_conn = connection;
	return NO_ERROR;

unlock_fail_free_connection:
	mutex_unlock(&adm_ctx->resource->conf_update);
fail_free_connection:
	drbd_transport_shutdown(connection, DESTROY_TRANSPORT);

	if (!list_empty(&connection->connections)) {
		drbd_unregister_connection(connection);
		synchronize_rcu();
	}
	drbd_put_connection(connection);
fail_put_transport:
	drbd_put_transport_class(tr_class);
fail:
	free_crypto(&crypto);
	kfree(new_net_conf);

	return retcode;
}

bool addr_eq_nla(const struct sockaddr_storage *addr, const int addr_len, const struct nlattr *nla)
{
	return	nla_len(nla) == addr_len && memcmp(nla_data(nla), addr, addr_len) == 0;
}

static enum drbd_ret_code
check_path_against_nla(const struct drbd_path *path,
		       const struct nlattr *my_addr, const struct nlattr *peer_addr)
{
	if (addr_eq_nla(&path->my_addr, path->my_addr_len, my_addr))
		return ERR_LOCAL_ADDR;
	if (addr_eq_nla(&path->peer_addr, path->peer_addr_len, peer_addr))
		return ERR_PEER_ADDR;
	return NO_ERROR;
}

static enum drbd_ret_code
check_path_usable(const struct drbd_config_context *adm_ctx,
		  const struct nlattr *my_addr, const struct nlattr *peer_addr)
{
	struct drbd_resource *resource;
	struct drbd_connection *connection;
	enum drbd_ret_code retcode;

	if (!(my_addr && peer_addr)) {
		drbd_msg_put_info(adm_ctx->reply_skb, "connection endpoint(s) missing");
		return ERR_INVALID_REQUEST;
	}

	/* No need for _rcu here. All reconfiguration is
	 * strictly serialized on genl_lock(). We are protected against
	 * concurrent reconfiguration/addition/deletion */
	for_each_resource(resource, &drbd_resources) {
		for_each_connection(connection, resource) {
			struct drbd_path *path;
			list_for_each_entry(path, &connection->transport.paths, list) {
				retcode = check_path_against_nla(path, my_addr, peer_addr);
				if (retcode == NO_ERROR)
					continue;
				/* Within the same resource, it is ok to use
				 * the same local endpoint several times */
				if (retcode == ERR_LOCAL_ADDR &&
				    resource == adm_ctx->resource)
					continue;
				return retcode;
			}
		}
	}
	return NO_ERROR;
}

static enum drbd_ret_code
adm_add_path(struct drbd_config_context *adm_ctx,  struct genl_info *info)
{
	struct drbd_transport *transport = &adm_ctx->connection->transport;
	struct nlattr *my_addr = NULL, *peer_addr = NULL;
	struct drbd_path *path;
	enum drbd_ret_code retcode;
	int err;

	/* parse and validate only */
	err = path_parms_from_attrs(NULL, info);
	if (err) {
		drbd_msg_put_info(adm_ctx->reply_skb, from_attrs_err_to_txt(err));
		return ERR_MANDATORY_TAG;
	}
	my_addr = nested_attr_tb[__nla_type(T_my_addr)];
	peer_addr = nested_attr_tb[__nla_type(T_peer_addr)];

	retcode = check_path_usable(adm_ctx, my_addr, peer_addr);
	if (retcode != NO_ERROR)
		return retcode;

	path = kzalloc(sizeof(struct drbd_path), GFP_KERNEL);
	if (!path)
		return ERR_NOMEM;

	path->my_addr_len = nla_len(my_addr);
	memcpy(&path->my_addr, nla_data(my_addr), path->my_addr_len);
	path->peer_addr_len = nla_len(peer_addr);
	memcpy(&path->peer_addr, nla_data(peer_addr), path->peer_addr_len);

	err = transport->ops->add_path(transport, path);
	if (err) {
		kfree(path);
		drbd_err(adm_ctx->connection, "add_path() failed with %d\n", err);
		drbd_msg_put_info(adm_ctx->reply_skb, "add_path on transport failed");
		return ERR_INVALID_REQUEST;
	}
	return NO_ERROR;
}

int drbd_adm_connect(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_config_context adm_ctx;
	struct connect_parms parms = { 0, };
	enum drbd_ret_code retcode;
	enum drbd_conn_state cstate;
	int err;

	retcode = drbd_adm_prepare(&adm_ctx, skb, info, DRBD_ADM_NEED_CONNECTION);
	if (!adm_ctx.reply_skb)
		return retcode;

	cstate = adm_ctx.connection->cstate[NOW];
	if (cstate != C_STANDALONE) {
		retcode = ERR_NET_CONFIGURED;
		goto out;
	}

	if (first_path(adm_ctx.connection) == NULL) {
		drbd_msg_put_info(adm_ctx.reply_skb, "connection endpoint(s) missing");
		retcode = ERR_INVALID_REQUEST;
		goto out;
	}

	if (info->attrs[DRBD_NLA_CONNECT_PARMS]) {
		err = connect_parms_from_attrs(&parms, info);
		if (err) {
			retcode = ERR_MANDATORY_TAG;
			drbd_msg_put_info(adm_ctx.reply_skb, from_attrs_err_to_txt(err));
			goto out;
		}
	}
	if (parms.discard_my_data) {
		if (adm_ctx.resource->role[NOW] == R_PRIMARY) {
			retcode = ERR_DISCARD_IMPOSSIBLE;
			goto out;
		}
		set_bit(CONN_DISCARD_MY_DATA, &adm_ctx.connection->flags);
	}
	if (parms.tentative)
		set_bit(CONN_DRY_RUN, &adm_ctx.connection->flags);

	retcode = change_cstate(adm_ctx.connection, C_UNCONNECTED, CS_VERBOSE);

out:
	drbd_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

int drbd_adm_new_peer(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_config_context adm_ctx;
	struct drbd_connection *connection;
	enum drbd_ret_code retcode;

	retcode = drbd_adm_prepare(&adm_ctx, skb, info, DRBD_ADM_NEED_PEER_NODE);
	if (!adm_ctx.reply_skb)
		return retcode;

	mutex_lock(&adm_ctx.resource->adm_mutex);

	if (adm_ctx.connection) {
		retcode = ERR_INVALID_REQUEST;
		drbd_msg_put_info(adm_ctx.reply_skb, "peer connection already exists");
	} else {
		retcode = adm_new_connection(&connection, &adm_ctx, info);
	}

	mutex_unlock(&adm_ctx.resource->adm_mutex);
	drbd_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

int drbd_adm_new_path(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_config_context adm_ctx;
	enum drbd_ret_code retcode;

	retcode = drbd_adm_prepare(&adm_ctx, skb, info, DRBD_ADM_NEED_CONNECTION);
	if (!adm_ctx.reply_skb)
		return retcode;

	/* remote transport endpoints need to be globaly unique */
	mutex_lock(&resources_mutex);
	mutex_lock(&adm_ctx.resource->adm_mutex);

	retcode = adm_add_path(&adm_ctx, info);

	mutex_unlock(&adm_ctx.resource->adm_mutex);
	mutex_unlock(&resources_mutex);
	drbd_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

static enum drbd_ret_code
adm_del_path(struct drbd_config_context *adm_ctx,  struct genl_info *info)
{
	struct drbd_transport *transport = &adm_ctx->connection->transport;
	struct nlattr *my_addr = NULL, *peer_addr = NULL;
	struct drbd_path *path;
	int err;

	/* parse and validate only */
	err = path_parms_from_attrs(NULL, info);
	if (err) {
		drbd_msg_put_info(adm_ctx->reply_skb, from_attrs_err_to_txt(err));
		return ERR_MANDATORY_TAG;
	}
	my_addr = nested_attr_tb[__nla_type(T_my_addr)];
	peer_addr = nested_attr_tb[__nla_type(T_peer_addr)];

	list_for_each_entry(path, &transport->paths, list) {
		if (!addr_eq_nla(&path->my_addr, path->my_addr_len, my_addr))
			continue;
		if (!addr_eq_nla(&path->peer_addr, path->peer_addr_len, peer_addr))
			continue;

		err = transport->ops->remove_path(transport, path);
		if (!err)
			kfree(path);
		break;
	}
	if (err) {
		drbd_err(adm_ctx->connection, "del_path() failed with %d\n", err);
		drbd_msg_put_info(adm_ctx->reply_skb, "del_path on transport failed");
		return ERR_INVALID_REQUEST;
	}
	return NO_ERROR;
}

int drbd_adm_del_path(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_config_context adm_ctx;
	enum drbd_ret_code retcode;

	retcode = drbd_adm_prepare(&adm_ctx, skb, info, DRBD_ADM_NEED_CONNECTION);
	if (!adm_ctx.reply_skb)
		return retcode;

	/* remote transport endpoints need to be globaly unique */
	mutex_lock(&resources_mutex);
	mutex_lock(&adm_ctx.resource->adm_mutex);

	retcode = adm_del_path(&adm_ctx, info);

	mutex_unlock(&adm_ctx.resource->adm_mutex);
	mutex_unlock(&resources_mutex);
	drbd_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

static enum drbd_state_rv conn_try_disconnect(struct drbd_connection *connection, bool force)
{
	struct drbd_resource *resource = connection->resource;
	enum drbd_state_rv rv;

    repeat:
	rv = change_cstate(connection, C_DISCONNECTING, force ? CS_HARD : 0);
	if (rv == SS_CW_FAILED_BY_PEER) {
		enum drbd_conn_state cstate;

		spin_lock_irq(&resource->req_lock);
		cstate = connection->cstate[NOW];
		spin_unlock_irq(&resource->req_lock);
		if (cstate < C_CONNECTED)
			goto repeat;
	}

	switch (rv) {
	case SS_ALREADY_STANDALONE:
		rv = SS_SUCCESS;
		break;
	case SS_IS_DISKLESS:
	case SS_LOWER_THAN_OUTDATED:
		rv = change_cstate(connection, C_DISCONNECTING, CS_HARD);
	default:;
		/* no special handling necessary */
	}
	return rv;
}

/* this cann only be called immediately after a successful
 * conn_try_disconnect, within the same resource->adm_mutex */
void del_connection(struct drbd_connection *connection)
{
	struct drbd_resource *resource = connection->resource;
	struct drbd_peer_device *peer_device;
	enum drbd_state_rv rv2;
	int vnr;

	/* No one else can reconfigure the network while I am here.
	 * The state handling only uses drbd_thread_stop_nowait(),
	 * we want to really wait here until the receiver is no more.
	 */
	drbd_thread_stop(&connection->receiver);

	/* Race breaker.  This additional state change request may be
	 * necessary, if this was a forced disconnect during a receiver
	 * restart.  We may have "killed" the receiver thread just
	 * after drbd_receiver() returned.  Typically, we should be
	 * C_STANDALONE already, now, and this becomes a no-op.
	 */
	rv2 = change_cstate(connection, C_STANDALONE, CS_VERBOSE | CS_HARD);
	if (rv2 < SS_SUCCESS)
		drbd_err(connection,
			"unexpected rv2=%d in del_connection()\n",
			rv2);
	/* Make sure the sender thread has actually stopped: state
	 * handling only does drbd_thread_stop_nowait().
	 */
	drbd_thread_stop(&connection->sender);

	drbd_unregister_connection(connection);

	/*
	 * Flush the resource work queue to make sure that no more
	 * events like state change notifications for this connection
	 * are queued: we want the "destroy" event to come last.
	 */
	drbd_flush_workqueue(&resource->work);

	mutex_lock(&notification_mutex);
	idr_for_each_entry(&connection->peer_devices, peer_device, vnr)
		notify_peer_device_state(NULL, 0, peer_device, NULL,
					 NOTIFY_DESTROY | NOTIFY_CONTINUES);
	notify_connection_state(NULL, 0, connection, NULL, NOTIFY_DESTROY);
	mutex_unlock(&notification_mutex);
	synchronize_rcu();
	drbd_put_connection(connection);
}

int adm_disconnect(struct sk_buff *skb, struct genl_info *info, bool destroy)
{
	struct drbd_config_context adm_ctx;
	struct disconnect_parms parms;
	struct drbd_connection *connection;
	enum drbd_state_rv rv;
	enum drbd_ret_code retcode;

	retcode = drbd_adm_prepare(&adm_ctx, skb, info, DRBD_ADM_NEED_CONNECTION);
	if (!adm_ctx.reply_skb)
		return retcode;

	memset(&parms, 0, sizeof(parms));
	if (info->attrs[DRBD_NLA_DISCONNECT_PARMS]) {
		int err = disconnect_parms_from_attrs(&parms, info);
		if (err) {
			retcode = ERR_MANDATORY_TAG;
			drbd_msg_put_info(adm_ctx.reply_skb, from_attrs_err_to_txt(err));
			goto fail;
		}
	}

	connection = adm_ctx.connection;
	mutex_lock(&adm_ctx.resource->adm_mutex);
	mutex_lock(&connection->resource->conf_update);
	rv = conn_try_disconnect(connection, parms.force_disconnect);
	if (rv >= SS_SUCCESS && destroy)
		del_connection(connection);
	mutex_unlock(&connection->resource->conf_update);
	if (rv < SS_SUCCESS)
		retcode = rv;  /* FIXME: Type mismatch. */
	else
		retcode = NO_ERROR;
	mutex_unlock(&adm_ctx.resource->adm_mutex);
 fail:
	drbd_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

int drbd_adm_disconnect(struct sk_buff *skb, struct genl_info *info)
{
	return adm_disconnect(skb, info, 0);
}

int drbd_adm_del_peer(struct sk_buff *skb, struct genl_info *info)
{
	return adm_disconnect(skb, info, 1);
}

void resync_after_online_grow(struct drbd_peer_device *peer_device)
{
	struct drbd_connection *connection = peer_device->connection;
	struct drbd_device *device = peer_device->device;
	bool sync_source;

	drbd_info(peer_device, "Resync of new storage after online grow\n");
	if (device->resource->role[NOW] != connection->peer_role[NOW])
		sync_source = (device->resource->role[NOW] == R_PRIMARY);
	else
		sync_source = test_bit(RESOLVE_CONFLICTS,
				       &peer_device->connection->transport.flags);

	if (!sync_source && connection->agreed_pro_version < 110) {
		stable_change_repl_state(peer_device, L_WF_SYNC_UUID,
					 CS_VERBOSE | CS_SERIALIZE);
		return;
	}
	drbd_start_resync(peer_device, sync_source ? L_SYNC_SOURCE : L_SYNC_TARGET);
}

int drbd_adm_resize(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_config_context adm_ctx;
	struct disk_conf *old_disk_conf, *new_disk_conf = NULL;
	struct resize_parms rs;
	struct drbd_device *device;
	enum drbd_ret_code retcode;
	enum determine_dev_size dd;
	bool change_al_layout = false;
	enum dds_flags ddsf;
	sector_t u_size;
	int err;
	struct drbd_peer_device *peer_device;
	bool has_primary;

	retcode = drbd_adm_prepare(&adm_ctx, skb, info, DRBD_ADM_NEED_MINOR);
	if (!adm_ctx.reply_skb)
		return retcode;

	mutex_lock(&adm_ctx.resource->adm_mutex);
	device = adm_ctx.device;
	if (!get_ldev(device)) {
		retcode = ERR_NO_DISK;
		goto fail;
	}

	memset(&rs, 0, sizeof(struct resize_parms));
	rs.al_stripes = device->ldev->md.al_stripes;
	rs.al_stripe_size = device->ldev->md.al_stripe_size_4k * 4;
	if (info->attrs[DRBD_NLA_RESIZE_PARMS]) {
		err = resize_parms_from_attrs(&rs, info);
		if (err) {
			retcode = ERR_MANDATORY_TAG;
			drbd_msg_put_info(adm_ctx.reply_skb, from_attrs_err_to_txt(err));
			goto fail_ldev;
		}
	}

	device = adm_ctx.device;
	for_each_peer_device(peer_device, device) {
		if (peer_device->repl_state[NOW] > L_ESTABLISHED) {
			retcode = ERR_RESIZE_RESYNC;
			goto fail_ldev;
		}
	}

	rcu_read_lock();
	u_size = rcu_dereference(device->ldev->disk_conf)->disk_size;
	rcu_read_unlock();
	if (u_size && u_size == (sector_t)rs.resize_size &&
	    device->ldev->md.al_stripes == rs.al_stripes &&
	    device->ldev->md.al_stripe_size_4k == rs.al_stripe_size / 4) {
		/* TODO once we can online-change the number of bitmap slots,
		 * we need add an "unchanged" check for those above. */
		/* This will be a no-op. Ignore. */
		retcode = NO_ERROR;
		goto fail_ldev;
	}

	has_primary = device->resource->role[NOW] == R_PRIMARY;
	if (!has_primary) {
		for_each_peer_device(peer_device, device) {
			if (peer_device->connection->peer_role[NOW] == R_PRIMARY) {
				has_primary = true;
				break;
			}
		}
	}
	if (!has_primary) {
		retcode = ERR_NO_PRIMARY;
		goto fail_ldev;
	}

	for_each_peer_device(peer_device, device) {
		if (rs.no_resync && peer_device->connection->agreed_pro_version < 93) {
			retcode = ERR_NEED_APV_93;
			goto fail_ldev;
		}
	}

	if (u_size != (sector_t)rs.resize_size) {
		new_disk_conf = kmalloc(sizeof(struct disk_conf), GFP_KERNEL);
		if (!new_disk_conf) {
			retcode = ERR_NOMEM;
			goto fail_ldev;
		}
	}

	if (device->ldev->md.al_stripes != rs.al_stripes ||
	    device->ldev->md.al_stripe_size_4k != rs.al_stripe_size / 4) {
		u32 al_size_k = rs.al_stripes * rs.al_stripe_size;

		if (al_size_k > (16 * 1024 * 1024)) {
			retcode = ERR_MD_LAYOUT_TOO_BIG;
			goto fail_ldev;
		}

		if (al_size_k < (32768 >> 10)) {
			retcode = ERR_MD_LAYOUT_TOO_SMALL;
			goto fail_ldev;
		}

		/* Removed this pre-condition while merging from 8.4 to 9.0
		if (device->state.conn != C_CONNECTED && !rs.resize_force) {
			retcode = ERR_MD_LAYOUT_CONNECTED;
			goto fail_ldev;
		} */

		change_al_layout = true;
	}

	device->ldev->known_size = drbd_get_capacity(device->ldev->backing_bdev);

	if (new_disk_conf) {
		mutex_lock(&device->resource->conf_update);
		old_disk_conf = device->ldev->disk_conf;
		*new_disk_conf = *old_disk_conf;
		new_disk_conf->disk_size = (sector_t)rs.resize_size;
		rcu_assign_pointer(device->ldev->disk_conf, new_disk_conf);
		mutex_unlock(&device->resource->conf_update);
		synchronize_rcu();
		kfree(old_disk_conf);
	}

	ddsf = (rs.resize_force ? DDSF_FORCED : 0) | (rs.no_resync ? DDSF_NO_RESYNC : 0);
	dd = drbd_determine_dev_size(device, ddsf, change_al_layout ? &rs : NULL);
	drbd_md_sync(device);
	put_ldev(device);
	if (dd == DS_ERROR) {
		retcode = ERR_NOMEM_BITMAP;
		goto fail;
	} else if (dd == DS_ERROR_SPACE_MD) {
		retcode = ERR_MD_LAYOUT_NO_FIT;
		goto fail;
	} else if (dd == DS_ERROR_SHRINK) {
		retcode = ERR_IMPLICIT_SHRINK;
		goto fail;
	}

	for_each_peer_device(peer_device, device) {
		if (peer_device->repl_state[NOW] == L_ESTABLISHED) {
			if (dd == DS_GREW)
				set_bit(RESIZE_PENDING, &peer_device->flags);
			drbd_send_uuids(peer_device, 0, 0);
			drbd_send_sizes(peer_device, 1, ddsf);
		}
	}

 fail:
	mutex_unlock(&adm_ctx.resource->adm_mutex);
	drbd_adm_finish(&adm_ctx, info, retcode);
	return 0;

 fail_ldev:
	put_ldev(device);
	goto fail;
}

int drbd_adm_resource_opts(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_config_context adm_ctx;
	enum drbd_ret_code retcode;
	struct res_opts res_opts;
	int err;

	retcode = drbd_adm_prepare(&adm_ctx, skb, info, DRBD_ADM_NEED_RESOURCE);
	if (!adm_ctx.reply_skb)
		return retcode;

	res_opts = adm_ctx.resource->res_opts;
	if (should_set_defaults(info))
		set_res_opts_defaults(&res_opts);

	err = res_opts_from_attrs_for_change(&res_opts, info);
	if (err && err != -ENOMSG) {
		retcode = ERR_MANDATORY_TAG;
		drbd_msg_put_info(adm_ctx.reply_skb, from_attrs_err_to_txt(err));
		goto fail;
	}

	mutex_lock(&adm_ctx.resource->adm_mutex);
	err = set_resource_options(adm_ctx.resource, &res_opts);
	if (err) {
		retcode = ERR_INVALID_REQUEST;
		if (err == -ENOMEM)
			retcode = ERR_NOMEM;
	}
	mutex_unlock(&adm_ctx.resource->adm_mutex);

fail:
	drbd_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

static enum drbd_state_rv invalidate_resync(struct drbd_peer_device *peer_device)
{
	struct drbd_resource *resource = peer_device->connection->resource;
	enum drbd_state_rv rv;

	drbd_flush_workqueue(&peer_device->connection->sender_work);

	rv = change_repl_state(peer_device, L_STARTING_SYNC_T, CS_SERIALIZE);

	if (rv < SS_SUCCESS && rv != SS_NEED_CONNECTION)
		rv = stable_change_repl_state(peer_device, L_STARTING_SYNC_T,
			CS_VERBOSE | CS_SERIALIZE);

	wait_event_interruptible(resource->state_wait,
				 peer_device->repl_state[NOW] != L_STARTING_SYNC_T);

	return rv;
}

static enum drbd_state_rv invalidate_no_resync(struct drbd_device *device) __must_hold(local)
{
	struct drbd_resource *resource = device->resource;
	struct drbd_peer_device *peer_device;
	struct drbd_connection *connection;
	unsigned long irq_flags;
	enum drbd_state_rv rv;

	begin_state_change(resource, &irq_flags, CS_VERBOSE);
	for_each_connection(connection, resource) {
		peer_device = conn_peer_device(connection, device->vnr);
		if (peer_device->repl_state[NOW] >= L_ESTABLISHED) {
			abort_state_change(resource, &irq_flags);
			return SS_UNKNOWN_ERROR;
		}
	}
	__change_disk_state(device, D_INCONSISTENT);
	rv = end_state_change(resource, &irq_flags);

	if (rv >= SS_SUCCESS) {
		drbd_bitmap_io(device, &drbd_bmio_set_all_n_write,
			       "set_n_write from invalidate",
			       BM_LOCK_CLEAR | BM_LOCK_BULK,
			       NULL);
	}

	return rv;
}

int drbd_adm_invalidate(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_config_context adm_ctx;
	struct drbd_peer_device *sync_from_peer_device = NULL;
	struct drbd_resource *resource;
	struct drbd_device *device;
	int retcode = 0; /* enum drbd_ret_code rsp. enum drbd_state_rv */

	retcode = drbd_adm_prepare(&adm_ctx, skb, info, DRBD_ADM_NEED_MINOR);
	if (!adm_ctx.reply_skb)
		return retcode;

	device = adm_ctx.device;

	if (!get_ldev(device)) {
		retcode = ERR_NO_DISK;
		goto out_no_ldev;
	}

	resource = device->resource;

	mutex_lock(&resource->adm_mutex);

	if (info->attrs[DRBD_NLA_INVALIDATE_PARMS]) {
		struct invalidate_parms inv = {};
		int err;

		inv.sync_from_peer_node_id = -1;
		err = invalidate_parms_from_attrs(&inv, info);
		if (err) {
			retcode = ERR_MANDATORY_TAG;
			drbd_msg_put_info(adm_ctx.reply_skb, from_attrs_err_to_txt(err));
			goto out_no_resume;
		}

		if (inv.sync_from_peer_node_id != -1) {
			struct drbd_connection *connection =
				drbd_connection_by_node_id(resource, inv.sync_from_peer_node_id);
			sync_from_peer_device = conn_peer_device(connection, device->vnr);
		}
	}

	/* If there is still bitmap IO pending, probably because of a previous
	 * resync just being finished, wait for it before requesting a new resync.
	 * Also wait for its after_state_ch(). */
	drbd_suspend_io(device, READ_AND_WRITE);
	wait_event(device->misc_wait, !atomic_read(&device->pending_bitmap_work.n));

	if (sync_from_peer_device) {
		retcode = invalidate_resync(sync_from_peer_device);
	} else {
		int retry = 3;
		do {
			struct drbd_connection *connection;

			for_each_connection(connection, resource) {
				struct drbd_peer_device *peer_device;

				peer_device = conn_peer_device(connection, device->vnr);
				retcode = invalidate_resync(peer_device);
				if (retcode >= SS_SUCCESS)
					goto out;
			}
			if (retcode != SS_NEED_CONNECTION)
				break;

			retcode = invalidate_no_resync(device);
		} while (retcode == SS_UNKNOWN_ERROR && retry--);
	}

out:
	drbd_resume_io(device);
out_no_resume:
	mutex_unlock(&resource->adm_mutex);
	put_ldev(device);
out_no_ldev:
	drbd_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

static int drbd_bmio_set_susp_al(struct drbd_device *device, struct drbd_peer_device *peer_device) __must_hold(local)
{
	int rv;

	rv = drbd_bmio_set_n_write(device, peer_device);
	drbd_try_suspend_al(device);
	return rv;
}

int drbd_adm_invalidate_peer(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_config_context adm_ctx;
	struct drbd_peer_device *peer_device;
	struct drbd_resource *resource;
	struct drbd_device *device;
	int retcode; /* enum drbd_ret_code rsp. enum drbd_state_rv */

	retcode = drbd_adm_prepare(&adm_ctx, skb, info, DRBD_ADM_NEED_PEER_DEVICE);
	if (!adm_ctx.reply_skb)
		return retcode;

	peer_device = adm_ctx.peer_device;
	device = peer_device->device;
	resource = device->resource;

	if (!get_ldev(device)) {
		retcode = ERR_NO_DISK;
		goto out;
	}

	mutex_lock(&resource->adm_mutex);

	drbd_suspend_io(device, READ_AND_WRITE);
	wait_event(device->misc_wait, !atomic_read(&device->pending_bitmap_work.n));
	drbd_flush_workqueue(&peer_device->connection->sender_work);
	retcode = stable_change_repl_state(peer_device, L_STARTING_SYNC_S, CS_SERIALIZE);

	if (retcode < SS_SUCCESS) {
		if (retcode == SS_NEED_CONNECTION && resource->role[NOW] == R_PRIMARY) {
			/* The peer will get a resync upon connect anyways.
			 * Just make that into a full resync. */
			retcode = change_peer_disk_state(peer_device, D_INCONSISTENT,
							 CS_VERBOSE | CS_WAIT_COMPLETE | CS_SERIALIZE);
			if (retcode >= SS_SUCCESS) {
				if (drbd_bitmap_io(adm_ctx.device, &drbd_bmio_set_susp_al,
						   "set_n_write from invalidate_peer",
						   BM_LOCK_CLEAR | BM_LOCK_BULK, peer_device))
					retcode = ERR_IO_MD_DISK;
			}
		} else
			retcode = stable_change_repl_state(peer_device, L_STARTING_SYNC_S,
							   CS_VERBOSE | CS_SERIALIZE);
	}
	drbd_resume_io(device);

	mutex_unlock(&resource->adm_mutex);
	put_ldev(device);
out:
	drbd_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

int drbd_adm_pause_sync(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_config_context adm_ctx;
	struct drbd_peer_device *peer_device;
	enum drbd_ret_code retcode;

	retcode = drbd_adm_prepare(&adm_ctx, skb, info, DRBD_ADM_NEED_PEER_DEVICE);
	if (!adm_ctx.reply_skb)
		return retcode;

	mutex_lock(&adm_ctx.resource->adm_mutex);

	peer_device = adm_ctx.peer_device;
	if (change_resync_susp_user(peer_device, true,
			CS_VERBOSE | CS_WAIT_COMPLETE | CS_SERIALIZE) == SS_NOTHING_TO_DO)
		retcode = ERR_PAUSE_IS_SET;

	mutex_unlock(&adm_ctx.resource->adm_mutex);
	drbd_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

int drbd_adm_resume_sync(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_config_context adm_ctx;
	struct drbd_peer_device *peer_device;
	enum drbd_ret_code retcode;

	retcode = drbd_adm_prepare(&adm_ctx, skb, info, DRBD_ADM_NEED_PEER_DEVICE);
	if (!adm_ctx.reply_skb)
		return retcode;

	mutex_lock(&adm_ctx.resource->adm_mutex);

	peer_device = adm_ctx.peer_device;
	if (change_resync_susp_user(peer_device, false,
			CS_VERBOSE | CS_WAIT_COMPLETE | CS_SERIALIZE) == SS_NOTHING_TO_DO) {

		if (peer_device->repl_state[NOW] == L_PAUSED_SYNC_S ||
		    peer_device->repl_state[NOW] == L_PAUSED_SYNC_T) {
			if (peer_device->resync_susp_dependency[NOW])
				retcode = ERR_PIC_AFTER_DEP;
			else if (peer_device->resync_susp_peer[NOW])
				retcode = ERR_PIC_PEER_DEP;
			else
				retcode = ERR_PAUSE_IS_CLEAR;
		} else {
			retcode = ERR_PAUSE_IS_CLEAR;
		}
	}

	mutex_unlock(&adm_ctx.resource->adm_mutex);
	drbd_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

int drbd_adm_suspend_io(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_config_context adm_ctx;
	struct drbd_resource *resource;
	enum drbd_ret_code retcode;

	retcode = drbd_adm_prepare(&adm_ctx, skb, info, DRBD_ADM_NEED_MINOR);
	if (!adm_ctx.reply_skb)
		return retcode;
	resource = adm_ctx.device->resource;
	mutex_lock(&resource->adm_mutex);

	retcode = stable_state_change(resource,
		change_io_susp_user(resource, true,
			      CS_VERBOSE | CS_WAIT_COMPLETE | CS_SERIALIZE));

	mutex_unlock(&resource->adm_mutex);
	drbd_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

int drbd_adm_resume_io(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_config_context adm_ctx;
	struct drbd_resource *resource;
	struct drbd_device *device;
	unsigned long irq_flags;
	int retcode; /* enum drbd_ret_code rsp. enum drbd_state_rv */

	retcode = drbd_adm_prepare(&adm_ctx, skb, info, DRBD_ADM_NEED_MINOR);
	if (!adm_ctx.reply_skb)
		return retcode;

	mutex_lock(&adm_ctx.resource->adm_mutex);
	device = adm_ctx.device;
	resource = device->resource;
	if (test_and_clear_bit(NEW_CUR_UUID, &device->flags))
		drbd_uuid_new_current(device, false);
	drbd_suspend_io(device, READ_AND_WRITE);
	begin_state_change(resource, &irq_flags, CS_VERBOSE | CS_WAIT_COMPLETE | CS_SERIALIZE);
	__change_io_susp_user(resource, false);
	__change_io_susp_no_data(resource, false);
	__change_io_susp_fencing(resource, false);
	retcode = end_state_change(resource, &irq_flags);
	if (retcode == SS_SUCCESS) {
		struct drbd_peer_device *peer_device;

		for_each_peer_device(peer_device, device) {
			struct drbd_connection *connection = peer_device->connection;

			if (peer_device->repl_state[NOW] < L_ESTABLISHED)
				tl_clear(connection);
			if (device->disk_state[NOW] == D_DISKLESS ||
			    device->disk_state[NOW] == D_FAILED ||
			    device->disk_state[NOW] == D_DETACHING)
				tl_restart(connection, FAIL_FROZEN_DISK_IO);
		}
	}
	drbd_resume_io(device);
	mutex_unlock(&adm_ctx.resource->adm_mutex);
	drbd_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

int drbd_adm_outdate(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_config_context adm_ctx;
	enum drbd_ret_code retcode;

	retcode = drbd_adm_prepare(&adm_ctx, skb, info, DRBD_ADM_NEED_MINOR);
	if (!adm_ctx.reply_skb)
		return retcode;
	mutex_lock(&adm_ctx.resource->adm_mutex);

	retcode = stable_state_change(adm_ctx.device->resource,
		change_disk_state(adm_ctx.device, D_OUTDATED,
			      CS_VERBOSE | CS_WAIT_COMPLETE | CS_SERIALIZE));

	mutex_unlock(&adm_ctx.resource->adm_mutex);
	drbd_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

static int nla_put_drbd_cfg_context(struct sk_buff *skb,
				    struct drbd_resource *resource,
				    struct drbd_connection *connection,
				    struct drbd_device *device)
{
	struct nlattr *nla;
	nla = nla_nest_start(skb, DRBD_NLA_CFG_CONTEXT);
	if (!nla)
		goto nla_put_failure;
	if (device)
		nla_put_u32(skb, T_ctx_volume, device->vnr);
	if (resource)
		nla_put_string(skb, T_ctx_resource_name, resource->name);
	if (connection) {
		nla_put_u32(skb, T_ctx_peer_node_id, connection->peer_node_id);
		rcu_read_lock();
		if (connection->transport.net_conf && connection->transport.net_conf->name)
			nla_put_string(skb, T_ctx_conn_name, connection->transport.net_conf->name);
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
 * The generic netlink dump callbacks are called outside the genl_lock(), so
 * they cannot use the simple attribute parsing code which uses global
 * attribute tables.
 */
static struct nlattr *find_cfg_context_attr(const struct nlmsghdr *nlh, int attr)
{
	const unsigned hdrlen = GENL_HDRLEN + GENL_MAGIC_FAMILY_HDRSZ;
	const int maxtype = ARRAY_SIZE(drbd_cfg_context_nl_policy) - 1;
	struct nlattr *nla;

	nla = nla_find(nlmsg_attrdata(nlh, hdrlen), nlmsg_attrlen(nlh, hdrlen),
		       DRBD_NLA_CFG_CONTEXT);
	if (!nla)
		return NULL;
	return drbd_nla_find_nested(maxtype, nla, __nla_type(attr));
}

static void resource_to_info(struct resource_info *, struct drbd_resource *);

int drbd_adm_dump_resources(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct drbd_genlmsghdr *dh;
	struct drbd_resource *resource;
	struct resource_info resource_info;
	struct resource_statistics resource_statistics;
	int err;

	rcu_read_lock();
	if (cb->args[0]) {
		for_each_resource_rcu(resource, &drbd_resources)
			if (resource == (struct drbd_resource *)cb->args[0])
				goto found_resource;
		err = 0;  /* resource was probably deleted */
		goto out;
	}
	resource = list_entry(&drbd_resources,
			      struct drbd_resource, resources);

found_resource:
	list_for_each_entry_continue_rcu(resource, &drbd_resources, resources) {
		goto put_result;
	}
	err = 0;
	goto out;

put_result:
	dh = genlmsg_put(skb, NETLINK_CB_PORTID(cb->skb),
			cb->nlh->nlmsg_seq, &drbd_genl_family,
			NLM_F_MULTI, DRBD_ADM_GET_RESOURCES);
	err = -ENOMEM;
	if (!dh)
		goto out;
	dh->minor = -1U;
	dh->ret_code = NO_ERROR;
	err = nla_put_drbd_cfg_context(skb, resource, NULL, NULL);
	if (err)
		goto out;
	err = res_opts_to_skb(skb, &resource->res_opts, !capable(CAP_SYS_ADMIN));
	if (err)
		goto out;
	resource_to_info(&resource_info, resource);
	err = resource_info_to_skb(skb, &resource_info, !capable(CAP_SYS_ADMIN));
	if (err)
		goto out;
	resource_statistics.res_stat_write_ordering = resource->write_ordering;
	err = resource_statistics_to_skb(skb, &resource_statistics, !capable(CAP_SYS_ADMIN));
	if (err)
		goto out;
	cb->args[0] = (long)resource;
	genlmsg_end(skb, dh);
	err = 0;

out:
	rcu_read_unlock();
	if (err)
		return err;
	return skb->len;
}

static void device_to_statistics(struct device_statistics *s,
				 struct drbd_device *device)
{
	memset(s, 0, sizeof(*s));
	s->dev_upper_blocked = !may_inc_ap_bio(device);
	if (get_ldev(device)) {
		struct drbd_md *md = &device->ldev->md;
		u64 *history_uuids = (u64 *)s->history_uuids;
		struct request_queue *q;
		int n;

		spin_lock_irq(&md->uuid_lock);
		s->dev_current_uuid = md->current_uuid;
		BUILD_BUG_ON(sizeof(s->history_uuids) != sizeof(md->history_uuids));
		for (n = 0; n < ARRAY_SIZE(md->history_uuids); n++)
			history_uuids[n] = md->history_uuids[n];
		s->history_uuids_len = sizeof(s->history_uuids);
		spin_unlock_irq(&md->uuid_lock);

		s->dev_disk_flags = md->flags;
		q = bdev_get_queue(device->ldev->backing_bdev);
		s->dev_lower_blocked =
			bdi_congested(&q->backing_dev_info,
				      (1 << BDI_async_congested) |
				      (1 << BDI_sync_congested));
		put_ldev(device);
	}
	s->dev_size = drbd_get_capacity(device->this_bdev);
	s->dev_read = device->read_cnt;
	s->dev_write = device->writ_cnt;
	s->dev_al_writes = device->al_writ_cnt;
	s->dev_bm_writes = device->bm_writ_cnt;
	s->dev_upper_pending = atomic_read(&device->ap_bio_cnt[READ]) +
		atomic_read(&device->ap_bio_cnt[WRITE]);
	s->dev_lower_pending = atomic_read(&device->local_cnt);
	s->dev_al_suspended = test_bit(AL_SUSPENDED, &device->flags);
	s->dev_exposed_data_uuid = device->exposed_data_uuid;
}

static int put_resource_in_arg0(struct netlink_callback *cb, int holder_nr)
{
	if (cb->args[0]) {
		struct drbd_resource *resource =
			(struct drbd_resource *)cb->args[0];
		kref_debug_put(&resource->kref_debug, holder_nr); /* , 6); , 7); */
		kref_put(&resource->kref, drbd_destroy_resource);
	}

	return 0;
}

int drbd_adm_dump_devices_done(struct netlink_callback *cb) {
	return put_resource_in_arg0(cb, 7);
}

static void device_to_info(struct device_info *, struct drbd_device *);

int drbd_adm_dump_devices(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct nlattr *resource_filter;
	struct drbd_resource *resource;
	struct drbd_device *uninitialized_var(device);
	int minor, err, retcode;
	struct drbd_genlmsghdr *dh;
	struct device_info device_info;
	struct device_statistics device_statistics;
	struct idr *idr_to_search;

	resource = (struct drbd_resource *)cb->args[0];
	if (!cb->args[0] && !cb->args[1]) {
		resource_filter = find_cfg_context_attr(cb->nlh, T_ctx_resource_name);
		if (resource_filter) {
			retcode = ERR_RES_NOT_KNOWN;
			resource = drbd_find_resource(nla_data(resource_filter));
			if (!resource)
				goto put_result;
			kref_debug_get(&resource->kref_debug, 7);
			cb->args[0] = (long)resource;
		}
	}

	rcu_read_lock();
	minor = cb->args[1];
	idr_to_search = resource ? &resource->devices : &drbd_devices;
	device = idr_get_next(idr_to_search, &minor);
	if (!device) {
		err = 0;
		goto out;
	}
	idr_for_each_entry_continue(idr_to_search, device, minor) {
		retcode = NO_ERROR;
		goto put_result;  /* only one iteration */
	}
	err = 0;
	goto out;  /* no more devices */

put_result:
	dh = genlmsg_put(skb, NETLINK_CB_PORTID(cb->skb),
			cb->nlh->nlmsg_seq, &drbd_genl_family,
			NLM_F_MULTI, DRBD_ADM_GET_DEVICES);
	err = -ENOMEM;
	if (!dh)
		goto out;
	dh->ret_code = retcode;
	dh->minor = -1U;
	if (retcode == NO_ERROR) {
		dh->minor = device->minor;
		err = nla_put_drbd_cfg_context(skb, device->resource, NULL, device);
		if (err)
			goto out;
		if (get_ldev(device)) {
			struct disk_conf *disk_conf =
				rcu_dereference(device->ldev->disk_conf);

			err = disk_conf_to_skb(skb, disk_conf, !capable(CAP_SYS_ADMIN));
			put_ldev(device);
			if (err)
				goto out;
		}
		err = device_conf_to_skb(skb, &device->device_conf, !capable(CAP_SYS_ADMIN));
		if (err)
			goto out;
		device_to_info(&device_info, device);
		err = device_info_to_skb(skb, &device_info, !capable(CAP_SYS_ADMIN));
		if (err)
			goto out;

		device_to_statistics(&device_statistics, device);
		err = device_statistics_to_skb(skb, &device_statistics, !capable(CAP_SYS_ADMIN));
		if (err)
			goto out;
		cb->args[1] = minor + 1;
	}
	genlmsg_end(skb, dh);
	err = 0;

out:
	rcu_read_unlock();
	if (err)
		return err;
	return skb->len;
}

int drbd_adm_dump_connections_done(struct netlink_callback *cb)
{
	return put_resource_in_arg0(cb, 6);
}

int connection_paths_to_skb(struct sk_buff *skb, struct drbd_connection *connection)
{
	struct drbd_path *path;
	struct nlattr *tla = nla_nest_start(skb, DRBD_NLA_PATH_PARMS);
	if (!tla)
		goto nla_put_failure;

	/* array of such paths. */
	list_for_each_entry(path, &connection->transport.paths, list) {
		if (nla_put(skb, T_my_addr, path->my_addr_len, &path->my_addr))
			goto nla_put_failure;
		if (nla_put(skb, T_peer_addr, path->peer_addr_len, &path->peer_addr))
			goto nla_put_failure;
	}
	nla_nest_end(skb, tla);
	return 0;

nla_put_failure:
	if (tla)
		nla_nest_cancel(skb, tla);
	return -EMSGSIZE;
}

enum { SINGLE_RESOURCE, ITERATE_RESOURCES };

int drbd_adm_dump_connections(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct nlattr *resource_filter;
	struct drbd_resource *resource = NULL, *next_resource;
	struct drbd_connection *uninitialized_var(connection);
	int err = 0, retcode;
	struct drbd_genlmsghdr *dh;
	struct connection_info connection_info;
	struct connection_statistics connection_statistics;

	rcu_read_lock();
	resource = (struct drbd_resource *)cb->args[0];
	if (!cb->args[0]) {
		resource_filter = find_cfg_context_attr(cb->nlh, T_ctx_resource_name);
		if (resource_filter) {
			retcode = ERR_RES_NOT_KNOWN;
			resource = drbd_find_resource(nla_data(resource_filter));
			if (!resource)
				goto put_result;
			kref_debug_get(&resource->kref_debug, 6);
			cb->args[0] = (long)resource;
			cb->args[1] = SINGLE_RESOURCE;
		}
	}
	if (!resource) {
		if (list_empty(&drbd_resources))
			goto out;
		resource = list_first_entry(&drbd_resources, struct drbd_resource, resources);
		kref_get(&resource->kref);
		kref_debug_get(&resource->kref_debug, 6);
		cb->args[0] = (long)resource;
		cb->args[1] = ITERATE_RESOURCES;
	}

    next_resource:
	rcu_read_unlock();
	mutex_lock(&resource->conf_update);
	rcu_read_lock();
	if (cb->args[2]) {
		for_each_connection_rcu(connection, resource)
			if (connection == (struct drbd_connection *)cb->args[2])
				goto found_connection;
		/* connection was probably deleted */
		goto no_more_connections;
	}
	connection = list_entry(&resource->connections, struct drbd_connection, connections);

found_connection:
	list_for_each_entry_continue_rcu(connection, &resource->connections, connections) {
		retcode = NO_ERROR;
		goto put_result;  /* only one iteration */
	}

no_more_connections:
	if (cb->args[1] == ITERATE_RESOURCES) {
		for_each_resource_rcu(next_resource, &drbd_resources) {
			if (next_resource == resource)
				goto found_resource;
		}
		/* resource was probably deleted */
	}
	goto out;

found_resource:
	list_for_each_entry_continue_rcu(next_resource, &drbd_resources, resources) {
		mutex_unlock(&resource->conf_update);
		kref_debug_put(&resource->kref_debug, 6);
		kref_put(&resource->kref, drbd_destroy_resource);
		resource = next_resource;
		kref_get(&resource->kref);
		kref_debug_get(&resource->kref_debug, 6);
		cb->args[0] = (long)resource;
		cb->args[2] = 0;
		goto next_resource;
	}
	goto out;  /* no more resources */

put_result:
	dh = genlmsg_put(skb, NETLINK_CB_PORTID(cb->skb),
			cb->nlh->nlmsg_seq, &drbd_genl_family,
			NLM_F_MULTI, DRBD_ADM_GET_CONNECTIONS);
	err = -ENOMEM;
	if (!dh)
		goto out;
	dh->ret_code = retcode;
	dh->minor = -1U;
	if (retcode == NO_ERROR) {
		struct net_conf *net_conf;

		err = nla_put_drbd_cfg_context(skb, resource, connection, NULL);
		if (err)
			goto out;
		net_conf = rcu_dereference(connection->transport.net_conf);
		if (net_conf) {
			err = net_conf_to_skb(skb, net_conf, !capable(CAP_SYS_ADMIN));
			if (err)
				goto out;
		}
		connection_to_info(&connection_info, connection);
		connection_paths_to_skb(skb, connection);
		err = connection_info_to_skb(skb, &connection_info, !capable(CAP_SYS_ADMIN));
		if (err)
			goto out;
		connection_statistics.conn_congested = test_bit(NET_CONGESTED, &connection->transport.flags);
		err = connection_statistics_to_skb(skb, &connection_statistics, !capable(CAP_SYS_ADMIN));
		if (err)
			goto out;
		cb->args[2] = (long)connection;
	}
	genlmsg_end(skb, dh);
	err = 0;

out:
	rcu_read_unlock();
	if (resource)
		mutex_unlock(&resource->conf_update);
	if (err)
		return err;
	return skb->len;
}

static void peer_device_to_statistics(struct peer_device_statistics *s,
				      struct drbd_peer_device *peer_device)
{
	struct drbd_device *device = peer_device->device;

	memset(s, 0, sizeof(*s));
	s->peer_dev_received = peer_device->recv_cnt;
	s->peer_dev_sent = peer_device->send_cnt;
	s->peer_dev_pending = atomic_read(&peer_device->ap_pending_cnt) +
			      atomic_read(&peer_device->rs_pending_cnt);
	s->peer_dev_unacked = atomic_read(&peer_device->unacked_cnt);
	s->peer_dev_out_of_sync = drbd_bm_total_weight(peer_device) << (BM_BLOCK_SHIFT - 9);
	s->peer_dev_resync_failed = peer_device->rs_failed << (BM_BLOCK_SHIFT - 9);
	if (get_ldev(device)) {
		struct drbd_md *md = &device->ldev->md;
		struct drbd_peer_md *peer_md = &md->peers[peer_device->node_id];

		spin_lock_irq(&md->uuid_lock);
		s->peer_dev_bitmap_uuid = peer_md->bitmap_uuid;
		spin_unlock_irq(&md->uuid_lock);
		s->peer_dev_flags = peer_md->flags;
		put_ldev(device);
	}
}

int drbd_adm_dump_peer_devices_done(struct netlink_callback *cb)
{
	return put_resource_in_arg0(cb, 9);
}

int drbd_adm_dump_peer_devices(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct nlattr *resource_filter;
	struct drbd_resource *resource;
	struct drbd_device *uninitialized_var(device);
	struct drbd_peer_device *peer_device = NULL;
	int minor, err, retcode;
	struct drbd_genlmsghdr *dh;
	struct idr *idr_to_search;

	resource = (struct drbd_resource *)cb->args[0];
	if (!cb->args[0] && !cb->args[1]) {
		resource_filter = find_cfg_context_attr(cb->nlh, T_ctx_resource_name);
		if (resource_filter) {
			retcode = ERR_RES_NOT_KNOWN;
			resource = drbd_find_resource(nla_data(resource_filter));
			if (!resource)
				goto put_result;
			kref_debug_get(&resource->kref_debug, 9);
		}
		cb->args[0] = (long)resource;
	}

	rcu_read_lock();
	minor = cb->args[1];
	idr_to_search = resource ? &resource->devices : &drbd_devices;
	device = idr_find(idr_to_search, minor);
	if (!device) {
next_device:
		minor++;
		cb->args[2] = 0;
		device = idr_get_next(idr_to_search, &minor);
		if (!device) {
			err = 0;
			goto out;
		}
	}
	if (cb->args[2]) {
		for_each_peer_device_rcu(peer_device, device)
			if (peer_device == (struct drbd_peer_device *)cb->args[2])
				goto found_peer_device;
		/* peer device was probably deleted */
		goto next_device;
	}
	/* Make peer_device point to the list head (not the first entry). */
	peer_device = list_entry(&device->peer_devices, struct drbd_peer_device, peer_devices);

found_peer_device:
	list_for_each_entry_continue_rcu(peer_device, &device->peer_devices, peer_devices) {
		retcode = NO_ERROR;
		goto put_result;  /* only one iteration */
	}
	goto next_device;

put_result:
	dh = genlmsg_put(skb, NETLINK_CB_PORTID(cb->skb),
			cb->nlh->nlmsg_seq, &drbd_genl_family,
			NLM_F_MULTI, DRBD_ADM_GET_PEER_DEVICES);
	err = -ENOMEM;
	if (!dh)
		goto out;
	dh->ret_code = retcode;
	dh->minor = -1U;
	if (retcode == NO_ERROR) {
		struct peer_device_info peer_device_info;
		struct peer_device_statistics peer_device_statistics;
		struct peer_device_conf *peer_device_conf;

		dh->minor = minor;
		err = nla_put_drbd_cfg_context(skb, device->resource, peer_device->connection, device);
		if (err)
			goto out;
		peer_device_to_info(&peer_device_info, peer_device);
		err = peer_device_info_to_skb(skb, &peer_device_info, !capable(CAP_SYS_ADMIN));
		if (err)
			goto out;
		peer_device_to_statistics(&peer_device_statistics, peer_device);
		err = peer_device_statistics_to_skb(skb, &peer_device_statistics, !capable(CAP_SYS_ADMIN));
		if (err)
			goto out;
		peer_device_conf = rcu_dereference(peer_device->conf);
		if (peer_device_conf) {
			err = peer_device_conf_to_skb(skb, peer_device_conf, !capable(CAP_SYS_ADMIN));
			if (err)
				goto out;
		}

		cb->args[1] = minor;
		cb->args[2] = (long)peer_device;
	}
	genlmsg_end(skb, dh);
	err = 0;

out:
	rcu_read_unlock();
	if (err)
		return err;
	return skb->len;
}

int drbd_adm_get_timeout_type(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_config_context adm_ctx;
	struct drbd_peer_device *peer_device;
	enum drbd_ret_code retcode;
	struct timeout_parms tp;
	int err;

	retcode = drbd_adm_prepare(&adm_ctx, skb, info, DRBD_ADM_NEED_PEER_DEVICE);
	if (!adm_ctx.reply_skb)
		return retcode;
	peer_device = adm_ctx.peer_device;

	tp.timeout_type =
		peer_device->disk_state[NOW] == D_OUTDATED ? UT_PEER_OUTDATED :
		test_bit(USE_DEGR_WFC_T, &peer_device->flags) ? UT_DEGRADED :
		UT_DEFAULT;

	err = timeout_parms_to_priv_skb(adm_ctx.reply_skb, &tp);
	if (err) {
		nlmsg_free(adm_ctx.reply_skb);
		return err;
	}

	drbd_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

int drbd_adm_start_ov(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_config_context adm_ctx;
	struct drbd_device *device;
	struct drbd_peer_device *peer_device;
	enum drbd_ret_code retcode;
	struct start_ov_parms parms;

	retcode = drbd_adm_prepare(&adm_ctx, skb, info, DRBD_ADM_NEED_PEER_DEVICE);
	if (!adm_ctx.reply_skb)
		return retcode;

	peer_device = adm_ctx.peer_device;
	device = peer_device->device;

	/* resume from last known position, if possible */
	parms.ov_start_sector = peer_device->ov_start_sector;
	parms.ov_stop_sector = ULLONG_MAX;
	if (info->attrs[DRBD_NLA_START_OV_PARMS]) {
		int err = start_ov_parms_from_attrs(&parms, info);
		if (err) {
			retcode = ERR_MANDATORY_TAG;
			drbd_msg_put_info(adm_ctx.reply_skb, from_attrs_err_to_txt(err));
			goto out;
		}
	}
	mutex_lock(&adm_ctx.resource->adm_mutex);

	/* w_make_ov_request expects position to be aligned */
	peer_device->ov_start_sector = parms.ov_start_sector & ~(BM_SECT_PER_BIT-1);
	peer_device->ov_stop_sector = parms.ov_stop_sector;

	/* If there is still bitmap IO pending, e.g. previous resync or verify
	 * just being finished, wait for it before requesting a new resync. */
	drbd_suspend_io(device, READ_AND_WRITE);
	wait_event(device->misc_wait, !atomic_read(&device->pending_bitmap_work.n));
	retcode = stable_change_repl_state(peer_device,
		L_VERIFY_S, CS_VERBOSE | CS_WAIT_COMPLETE | CS_SERIALIZE);
	drbd_resume_io(device);

	mutex_unlock(&adm_ctx.resource->adm_mutex);
out:
	drbd_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

static bool should_skip_initial_sync(struct drbd_peer_device *peer_device)
{
	return peer_device->repl_state[NOW] == L_ESTABLISHED &&
	       peer_device->connection->agreed_pro_version >= 90 &&
	       drbd_current_uuid(peer_device->device) == UUID_JUST_CREATED;
}

int drbd_adm_new_c_uuid(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_config_context adm_ctx;
	struct drbd_device *device;
	struct drbd_peer_device *peer_device;
	enum drbd_ret_code retcode;
	int err;
	struct new_c_uuid_parms args;

	retcode = drbd_adm_prepare(&adm_ctx, skb, info, DRBD_ADM_NEED_MINOR);
	if (!adm_ctx.reply_skb)
		return retcode;

	device = adm_ctx.device;
	memset(&args, 0, sizeof(args));
	if (info->attrs[DRBD_NLA_NEW_C_UUID_PARMS]) {
		err = new_c_uuid_parms_from_attrs(&args, info);
		if (err) {
			retcode = ERR_MANDATORY_TAG;
			drbd_msg_put_info(adm_ctx.reply_skb, from_attrs_err_to_txt(err));
			goto out_nolock;
		}
	}

	mutex_lock(&adm_ctx.resource->adm_mutex);
	down(&device->resource->state_sem);

	if (!get_ldev(device)) {
		retcode = ERR_NO_DISK;
		goto out;
	}

	/* this is "skip initial sync", assume to be clean */
	for_each_peer_device(peer_device, device) {
		if (args.clear_bm && should_skip_initial_sync(peer_device))
			drbd_info(peer_device, "Preparing to skip initial sync\n");
		else if (peer_device->repl_state[NOW] != L_OFF) {
			retcode = ERR_CONNECTED;
			goto out_dec;
		}
	}

	for_each_peer_device(peer_device, device)
		drbd_uuid_set_bitmap(peer_device, 0); /* Rotate UI_BITMAP to History 1, etc... */
	drbd_uuid_new_current(device, false); /* New current, previous to UI_BITMAP */

	if (args.clear_bm) {
		unsigned long irq_flags;

		err = drbd_bitmap_io(device, &drbd_bmio_clear_all_n_write,
			"clear_n_write from new_c_uuid", BM_LOCK_ALL, NULL);
		if (err) {
			drbd_err(device, "Writing bitmap failed with %d\n",err);
			retcode = ERR_IO_MD_DISK;
		}
		for_each_peer_device(peer_device, device) {
			if (should_skip_initial_sync(peer_device)) {
				drbd_send_uuids(peer_device, UUID_FLAG_SKIP_INITIAL_SYNC, 0);
				_drbd_uuid_set_bitmap(peer_device, 0);
				drbd_print_uuids(peer_device, "cleared bitmap UUID");
			}
		}
		begin_state_change(device->resource, &irq_flags, CS_VERBOSE);
		__change_disk_state(device, D_UP_TO_DATE);
		for_each_peer_device(peer_device, device) {
			if (should_skip_initial_sync(peer_device))
				__change_peer_disk_state(peer_device, D_UP_TO_DATE);
		}
		end_state_change(device->resource, &irq_flags);
	}

	drbd_md_sync(device);
out_dec:
	put_ldev(device);
out:
	up(&device->resource->state_sem);
out_nolock:
	mutex_unlock(&adm_ctx.resource->adm_mutex);
	drbd_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

static enum drbd_ret_code
drbd_check_resource_name(struct drbd_config_context *adm_ctx)
{
	const char *name = adm_ctx->resource_name;
	if (!name || !name[0]) {
		drbd_msg_put_info(adm_ctx->reply_skb, "resource name missing");
		return ERR_MANDATORY_TAG;
	}
	/* if we want to use these in sysfs/configfs/debugfs some day,
	 * we must not allow slashes */
	if (strchr(name, '/')) {
		drbd_msg_put_info(adm_ctx->reply_skb, "invalid resource name");
		return ERR_INVALID_REQUEST;
	}
	return NO_ERROR;
}

static void resource_to_info(struct resource_info *info,
			     struct drbd_resource *resource)
{
	info->res_role = resource->role[NOW];
	info->res_susp = resource->susp[NOW];
	info->res_susp_nod = resource->susp_nod[NOW];
	info->res_susp_fen = resource->susp_fen[NOW];
}

int drbd_adm_new_resource(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_config_context adm_ctx;
	struct drbd_resource *resource;
	enum drbd_ret_code retcode;
	struct res_opts res_opts;
	int err;

	retcode = drbd_adm_prepare(&adm_ctx, skb, info, 0);
	if (!adm_ctx.reply_skb)
		return retcode;

	set_res_opts_defaults(&res_opts);
	err = res_opts_from_attrs(&res_opts, info);
	if (err) {
		retcode = ERR_MANDATORY_TAG;
		drbd_msg_put_info(adm_ctx.reply_skb, from_attrs_err_to_txt(err));
		goto out;
	}

	retcode = drbd_check_resource_name(&adm_ctx);
	if (retcode != NO_ERROR)
		goto out;

	if (adm_ctx.resource)
		goto out;

	if (res_opts.node_id < 0 || res_opts.node_id >= DRBD_NODE_ID_MAX) {
		pr_err("drbd: invalid node id (%d)\n", res_opts.node_id);
		retcode = ERR_INVALID_REQUEST;
		goto out;
	}

	if (!try_module_get(THIS_MODULE)) {
		pr_err("drbd: Could not get a module reference\n");
		retcode = ERR_INVALID_REQUEST;
		goto out;
	}

	mutex_lock(&resources_mutex);
	resource = drbd_create_resource(adm_ctx.resource_name, &res_opts);
	mutex_unlock(&resources_mutex);

	if (resource) {
		struct resource_info resource_info;

		mutex_lock(&notification_mutex);
		resource_to_info(&resource_info, resource);
		notify_resource_state(NULL, 0, resource, &resource_info, NOTIFY_CREATE);
		mutex_unlock(&notification_mutex);
	} else {
		module_put(THIS_MODULE);
		retcode = ERR_NOMEM;
	}

out:
	drbd_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

static void device_to_info(struct device_info *info,
			   struct drbd_device *device)
{
	info->dev_disk_state = device->disk_state[NOW];
}

int drbd_adm_new_minor(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_config_context adm_ctx;
	struct drbd_genlmsghdr *dh = info->userhdr;
	struct device_conf device_conf;
	struct drbd_resource *resource;
	struct drbd_device *device;
	enum drbd_ret_code retcode;
	int err;

	retcode = drbd_adm_prepare(&adm_ctx, skb, info, DRBD_ADM_NEED_RESOURCE);
	if (!adm_ctx.reply_skb)
		return retcode;

	set_device_conf_defaults(&device_conf);
	err = device_conf_from_attrs(&device_conf, info);
	if (err && err != -ENOMSG) {
		retcode = ERR_MANDATORY_TAG;
		drbd_msg_put_info(adm_ctx.reply_skb, from_attrs_err_to_txt(err));
		goto out;
	}

	if (dh->minor > MINORMASK) {
		drbd_msg_put_info(adm_ctx.reply_skb, "requested minor out of range");
		retcode = ERR_INVALID_REQUEST;
		goto out;
	}
	if (adm_ctx.volume > DRBD_VOLUME_MAX) {
		drbd_msg_put_info(adm_ctx.reply_skb, "requested volume id out of range");
		retcode = ERR_INVALID_REQUEST;
		goto out;
	}

	if (adm_ctx.device)
		goto out;

	resource = adm_ctx.resource;
	mutex_lock(&resource->conf_update);
	for(;;) {
		retcode = drbd_create_device(&adm_ctx, dh->minor, &device_conf, &device);
		if (retcode != ERR_NOMEM ||
		    schedule_timeout_interruptible(HZ / 10))
			break;
		/* Keep retrying until the memory allocations eventually succeed. */
	}
	if (retcode == NO_ERROR) {
		struct drbd_peer_device *peer_device;
		struct device_info info;
		unsigned int peer_devices = 0;
		enum drbd_notification_type flags;

		for_each_peer_device(peer_device, device)
			peer_devices++;

		device_to_info(&info, device);
		mutex_lock(&notification_mutex);
		flags = (peer_devices--) ? NOTIFY_CONTINUES : 0;
		notify_device_state(NULL, 0, device, &info, NOTIFY_CREATE | flags);
		for_each_peer_device(peer_device, device) {
			struct peer_device_info peer_device_info;

			peer_device_to_info(&peer_device_info, peer_device);
			flags = (peer_devices--) ? NOTIFY_CONTINUES : 0;
			notify_peer_device_state(NULL, 0, peer_device, &peer_device_info,
						 NOTIFY_CREATE | flags);
		}
		mutex_unlock(&notification_mutex);
	}
	mutex_unlock(&resource->conf_update);
out:
	drbd_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

static enum drbd_ret_code adm_del_minor(struct drbd_device *device)
{
	struct drbd_resource *resource = device->resource;
	struct drbd_peer_device *peer_device;
	enum drbd_ret_code ret;
	u64 im;

	spin_lock_irq(&resource->req_lock);
	if (device->disk_state[NOW] == D_DISKLESS &&
	    device->open_ro_cnt == 0 && device->open_rw_cnt == 0) {
		set_bit(UNREGISTERED, &device->flags);
		ret = NO_ERROR;
	} else {
		ret = ERR_MINOR_CONFIGURED;
	}
	spin_unlock_irq(&resource->req_lock);

	if (ret != NO_ERROR)
		return ret;

	for_each_peer_device_ref(peer_device, im, device)
		stable_change_repl_state(peer_device, L_OFF,
					 CS_VERBOSE | CS_WAIT_COMPLETE);

	/*
	 * Flush the resource work queue to make sure that no more events like
	 * state change notifications for this device are queued: we want the
	 * "destroy" event to come last.
	 */
	drbd_flush_workqueue(&resource->work);

	drbd_unregister_device(device);

	mutex_lock(&notification_mutex);
	for_each_peer_device_ref(peer_device, im, device)
		notify_peer_device_state(NULL, 0, peer_device, NULL,
					 NOTIFY_DESTROY | NOTIFY_CONTINUES);
	notify_device_state(NULL, 0, device, NULL, NOTIFY_DESTROY);
	mutex_unlock(&notification_mutex);
	synchronize_rcu();
	drbd_put_device(device);

	return ret;
}

int drbd_adm_del_minor(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_config_context adm_ctx;
	enum drbd_ret_code retcode;

	retcode = drbd_adm_prepare(&adm_ctx, skb, info, DRBD_ADM_NEED_MINOR);
	if (!adm_ctx.reply_skb)
		return retcode;

	mutex_lock(&adm_ctx.resource->adm_mutex);
	retcode = adm_del_minor(adm_ctx.device);
	mutex_unlock(&adm_ctx.resource->adm_mutex);

	drbd_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

static int adm_del_resource(struct drbd_resource *resource)
{
	int err;

	/*
	 * Flush the resource work queue to make sure that no more events like
	 * state change notifications are queued: we want the "destroy" event
	 * to come last.
	 */
	drbd_flush_workqueue(&resource->work);

	mutex_lock(&resources_mutex);
	err = ERR_NET_CONFIGURED;
	if (!list_empty(&resource->connections))
		goto out;
	err = ERR_RES_IN_USE;
	if (!idr_is_empty(&resource->devices))
		goto out;
	err = NO_ERROR;

	mutex_lock(&notification_mutex);
	notify_resource_state(NULL, 0, resource, NULL, NOTIFY_DESTROY);
	mutex_unlock(&notification_mutex);

	list_del_rcu(&resource->resources);
	drbd_debugfs_resource_cleanup(resource);
	synchronize_rcu();
	drbd_free_resource(resource);
out:
	mutex_unlock(&resources_mutex);
	return err;
}

int drbd_adm_down(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_config_context adm_ctx;
	struct drbd_resource *resource;
	struct drbd_connection *connection, *tmp;
	struct drbd_device *device;
	int retcode; /* enum drbd_ret_code rsp. enum drbd_state_rv */
	unsigned i;

	retcode = drbd_adm_prepare(&adm_ctx, skb, info,
			DRBD_ADM_NEED_RESOURCE | DRBD_ADM_IGNORE_VERSION);
	if (!adm_ctx.reply_skb)
		return retcode;

	resource = adm_ctx.resource;
	mutex_lock(&resource->adm_mutex);
	/* demote */
	retcode = drbd_set_role(resource, R_SECONDARY, false);
	if (retcode < SS_SUCCESS) {
		drbd_msg_put_info(adm_ctx.reply_skb, "failed to demote");
		goto out;
	}

	mutex_lock(&resource->conf_update);
	for_each_connection_safe(connection, tmp, resource) {
		retcode = conn_try_disconnect(connection, 0);
		if (retcode >= SS_SUCCESS) {
			del_connection(connection);
		} else {
			drbd_msg_put_info(adm_ctx.reply_skb, "failed to disconnect");
			goto unlock_out;
		}
	}

	/* detach */
	idr_for_each_entry(&resource->devices, device, i) {
		retcode = adm_detach(device, 0);
		if (retcode < SS_SUCCESS || retcode > NO_ERROR) {
			drbd_msg_put_info(adm_ctx.reply_skb, "failed to detach");
			goto unlock_out;
		}
	}

	/* delete volumes */
	idr_for_each_entry(&resource->devices, device, i) {
		retcode = adm_del_minor(device);
		if (retcode != NO_ERROR) {
			/* "can not happen" */
			drbd_msg_put_info(adm_ctx.reply_skb, "failed to delete volume");
			goto unlock_out;
		}
	}

	retcode = adm_del_resource(resource);

unlock_out:
	mutex_unlock(&resource->conf_update);
out:
	mutex_unlock(&resource->adm_mutex);
	drbd_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

int drbd_adm_del_resource(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_config_context adm_ctx;
	enum drbd_ret_code retcode;

	retcode = drbd_adm_prepare(&adm_ctx, skb, info, DRBD_ADM_NEED_RESOURCE);
	if (!adm_ctx.reply_skb)
		return retcode;

	retcode = adm_del_resource(adm_ctx.resource);

	drbd_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

static int nla_put_notification_header(struct sk_buff *msg,
				       enum drbd_notification_type type)
{
	struct drbd_notification_header nh = {
		.nh_type = type,
	};

	return drbd_notification_header_to_skb(msg, &nh, true);
}

void notify_resource_state(struct sk_buff *skb,
			   unsigned int seq,
			   struct drbd_resource *resource,
			   struct resource_info *resource_info,
			   enum drbd_notification_type type)
{
	struct resource_statistics resource_statistics;
	struct drbd_genlmsghdr *dh;
	bool multicast = false;
	int err;

	if (!skb) {
		seq = atomic_inc_return(&drbd_genl_seq);
		skb = genlmsg_new(NLMSG_GOODSIZE, GFP_NOIO);
		err = -ENOMEM;
		if (!skb)
			goto failed;
		multicast = true;
	}

	err = -EMSGSIZE;
	dh = genlmsg_put(skb, 0, seq, &drbd_genl_family, 0, DRBD_RESOURCE_STATE);
	if (!dh)
		goto nla_put_failure;
	dh->minor = -1U;
	dh->ret_code = NO_ERROR;
	if (nla_put_drbd_cfg_context(skb, resource, NULL, NULL) ||
	    nla_put_notification_header(skb, type) ||
	    ((type & ~NOTIFY_FLAGS) != NOTIFY_DESTROY &&
	     resource_info_to_skb(skb, resource_info, true)))
		goto nla_put_failure;
	resource_statistics.res_stat_write_ordering = resource->write_ordering;
	err = resource_statistics_to_skb(skb, &resource_statistics, !capable(CAP_SYS_ADMIN));
	if (err)
		goto nla_put_failure;
	genlmsg_end(skb, dh);
	if (multicast) {
		err = drbd_genl_multicast_events(skb, GFP_NOWAIT);
		/* skb has been consumed or freed in netlink_broadcast() */
		if (err && err != -ESRCH)
			goto failed;
	}
	return;

nla_put_failure:
	nlmsg_free(skb);
failed:
	drbd_err(resource, "Error %d while broadcasting event. Event seq:%u\n",
			err, seq);
}

void notify_device_state(struct sk_buff *skb,
			 unsigned int seq,
			 struct drbd_device *device,
			 struct device_info *device_info,
			 enum drbd_notification_type type)
{
	struct device_statistics device_statistics;
	struct drbd_genlmsghdr *dh;
	bool multicast = false;
	int err;

	if (!skb) {
		seq = atomic_inc_return(&drbd_genl_seq);
		skb = genlmsg_new(NLMSG_GOODSIZE, GFP_NOIO);
		err = -ENOMEM;
		if (!skb)
			goto failed;
		multicast = true;
	}

	err = -EMSGSIZE;
	dh = genlmsg_put(skb, 0, seq, &drbd_genl_family, 0, DRBD_DEVICE_STATE);
	if (!dh)
		goto nla_put_failure;
	dh->minor = device->minor;
	dh->ret_code = NO_ERROR;
	if (nla_put_drbd_cfg_context(skb, device->resource, NULL, device) ||
	    nla_put_notification_header(skb, type) ||
	    ((type & ~NOTIFY_FLAGS) != NOTIFY_DESTROY &&
	     device_info_to_skb(skb, device_info, true)))
		goto nla_put_failure;
	device_to_statistics(&device_statistics, device);
	device_statistics_to_skb(skb, &device_statistics, !capable(CAP_SYS_ADMIN));
	genlmsg_end(skb, dh);
	if (multicast) {
		err = drbd_genl_multicast_events(skb, GFP_NOWAIT);
		/* skb has been consumed or freed in netlink_broadcast() */
		if (err && err != -ESRCH)
			goto failed;
	}
	return;

nla_put_failure:
	nlmsg_free(skb);
failed:
	drbd_err(device, "Error %d while broadcasting event. Event seq:%u\n",
		 err, seq);
}

/* open coded path_parms_to_skb() iterating of the list */
void notify_connection_state(struct sk_buff *skb,
			     unsigned int seq,
			     struct drbd_connection *connection,
			     struct connection_info *connection_info,
			     enum drbd_notification_type type)
{
	struct connection_statistics connection_statistics;
	struct drbd_genlmsghdr *dh;
	bool multicast = false;
	int err;

	if (!skb) {
		seq = atomic_inc_return(&drbd_genl_seq);
		skb = genlmsg_new(NLMSG_GOODSIZE, GFP_NOIO);
		err = -ENOMEM;
		if (!skb)
			goto failed;
		multicast = true;
	}

	err = -EMSGSIZE;
	dh = genlmsg_put(skb, 0, seq, &drbd_genl_family, 0, DRBD_CONNECTION_STATE);
	if (!dh)
		goto nla_put_failure;
	dh->minor = -1U;
	dh->ret_code = NO_ERROR;
	if (nla_put_drbd_cfg_context(skb, connection->resource, connection, NULL) ||
	    nla_put_notification_header(skb, type) ||
	    ((type & ~NOTIFY_FLAGS) != NOTIFY_DESTROY &&
	     connection_info_to_skb(skb, connection_info, true)))
		goto nla_put_failure;
	connection_paths_to_skb(skb, connection);
	connection_statistics.conn_congested = test_bit(NET_CONGESTED, &connection->transport.flags);
	connection_statistics_to_skb(skb, &connection_statistics, !capable(CAP_SYS_ADMIN));
	genlmsg_end(skb, dh);
	if (multicast) {
		err = drbd_genl_multicast_events(skb, GFP_NOWAIT);
		/* skb has been consumed or freed in netlink_broadcast() */
		if (err && err != -ESRCH)
			goto failed;
	}
	return;

nla_put_failure:
	nlmsg_free(skb);
failed:
	drbd_err(connection, "Error %d while broadcasting event. Event seq:%u\n",
		 err, seq);
}

void notify_peer_device_state(struct sk_buff *skb,
			      unsigned int seq,
			      struct drbd_peer_device *peer_device,
			      struct peer_device_info *peer_device_info,
			      enum drbd_notification_type type)
{
	struct peer_device_statistics peer_device_statistics;
	struct drbd_resource *resource = peer_device->device->resource;
	struct drbd_genlmsghdr *dh;
	bool multicast = false;
	int err;

	if (!skb) {
		seq = atomic_inc_return(&drbd_genl_seq);
		skb = genlmsg_new(NLMSG_GOODSIZE, GFP_NOIO);
		err = -ENOMEM;
		if (!skb)
			goto failed;
		multicast = true;
	}

	err = -EMSGSIZE;
	dh = genlmsg_put(skb, 0, seq, &drbd_genl_family, 0, DRBD_PEER_DEVICE_STATE);
	if (!dh)
		goto nla_put_failure;
	dh->minor = -1U;
	dh->ret_code = NO_ERROR;
	if (nla_put_drbd_cfg_context(skb, resource, peer_device->connection, peer_device->device) ||
	    nla_put_notification_header(skb, type) ||
	    ((type & ~NOTIFY_FLAGS) != NOTIFY_DESTROY &&
	     peer_device_info_to_skb(skb, peer_device_info, true)))
		goto nla_put_failure;
	peer_device_to_statistics(&peer_device_statistics, peer_device);
	peer_device_statistics_to_skb(skb, &peer_device_statistics, !capable(CAP_SYS_ADMIN));
	genlmsg_end(skb, dh);
	if (multicast) {
		err = drbd_genl_multicast_events(skb, GFP_NOWAIT);
		/* skb has been consumed or freed in netlink_broadcast() */
		if (err && err != -ESRCH)
			goto failed;
	}
	return;

nla_put_failure:
	nlmsg_free(skb);
failed:
	drbd_err(peer_device, "Error %d while broadcasting event. Event seq:%u\n",
		 err, seq);
}

void notify_helper(enum drbd_notification_type type,
		   struct drbd_device *device, struct drbd_connection *connection,
		   const char *name, int status)
{
	struct drbd_resource *resource = device ? device->resource : connection->resource;
	struct drbd_helper_info helper_info;
	unsigned int seq = atomic_inc_return(&drbd_genl_seq);
	struct sk_buff *skb = NULL;
	struct drbd_genlmsghdr *dh;
	int err;

	strlcpy(helper_info.helper_name, name, sizeof(helper_info.helper_name));
	helper_info.helper_name_len = min(strlen(name), sizeof(helper_info.helper_name));
	helper_info.helper_status = status;

	skb = genlmsg_new(NLMSG_GOODSIZE, GFP_NOIO);
	err = -ENOMEM;
	if (!skb)
		goto fail;

	err = -EMSGSIZE;
	dh = genlmsg_put(skb, 0, seq, &drbd_genl_family, 0, DRBD_HELPER);
	if (!dh)
		goto fail;
	dh->minor = device ? device->minor : -1;
	dh->ret_code = NO_ERROR;
	mutex_lock(&notification_mutex);
	if (nla_put_drbd_cfg_context(skb, resource, connection, device) ||
	    nla_put_notification_header(skb, type) ||
	    drbd_helper_info_to_skb(skb, &helper_info, true))
		goto unlock_fail;
	genlmsg_end(skb, dh);
	err = drbd_genl_multicast_events(skb, GFP_NOWAIT);
	skb = NULL;
	/* skb has been consumed or freed in netlink_broadcast() */
	if (err && err != -ESRCH)
		goto unlock_fail;
	mutex_unlock(&notification_mutex);
	return;

unlock_fail:
	mutex_unlock(&notification_mutex);
fail:
	nlmsg_free(skb);
	drbd_err(resource, "Error %d while broadcasting event. Event seq:%u\n",
		 err, seq);
}

static void notify_initial_state_done(struct sk_buff *skb, unsigned int seq)
{
	struct drbd_genlmsghdr *dh;
	int err;

	err = -EMSGSIZE;
	dh = genlmsg_put(skb, 0, seq, &drbd_genl_family, 0, DRBD_INITIAL_STATE_DONE);
	if (!dh)
		goto nla_put_failure;
	dh->minor = -1U;
	dh->ret_code = NO_ERROR;
	if (nla_put_notification_header(skb, NOTIFY_EXISTS))
		goto nla_put_failure;
	genlmsg_end(skb, dh);
	return;

nla_put_failure:
	nlmsg_free(skb);
	pr_err("Error %d sending event. Event seq:%u\n", err, seq);
}

static void free_state_changes(struct list_head *list)
{
	while (!list_empty(list)) {
		struct drbd_state_change *state_change =
			list_first_entry(list, struct drbd_state_change, list);
		list_del(&state_change->list);
		forget_state_change(state_change);
	}
}

static unsigned int notifications_for_state_change(struct drbd_state_change *state_change)
{
	return 1 +
	       state_change->n_connections +
	       state_change->n_devices +
	       state_change->n_devices * state_change->n_connections;
}

static int get_initial_state(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct drbd_state_change *state_change = (struct drbd_state_change *)cb->args[0];
	unsigned int seq = cb->args[2];
	unsigned int n;
	enum drbd_notification_type flags = 0;

	/* There is no need for taking notification_mutex here: it doesn't
	   matter if the initial state events mix with later state chage
	   events; we can always tell the events apart by the NOTIFY_EXISTS
	   flag. */

	cb->args[5]--;
	if (cb->args[5] == 1) {
		notify_initial_state_done(skb, seq);
		goto out;
	}
	n = cb->args[4]++;
	if (cb->args[4] < cb->args[3])
		flags |= NOTIFY_CONTINUES;
	if (n < 1) {
		notify_resource_state_change(skb, seq, state_change->resource,
					     NOTIFY_EXISTS | flags);
		goto next;
	}
	n--;
	if (n < state_change->n_connections) {
		notify_connection_state_change(skb, seq, &state_change->connections[n],
					       NOTIFY_EXISTS | flags);
		goto next;
	}
	n -= state_change->n_connections;
	if (n < state_change->n_devices) {
		notify_device_state_change(skb, seq, &state_change->devices[n],
					   NOTIFY_EXISTS | flags);
		goto next;
	}
	n -= state_change->n_devices;
	if (n < state_change->n_devices * state_change->n_connections) {
		notify_peer_device_state_change(skb, seq, &state_change->peer_devices[n],
						NOTIFY_EXISTS | flags);
		goto next;
	}

next:
	if (cb->args[4] == cb->args[3]) {
		struct drbd_state_change *next_state_change =
			list_entry(state_change->list.next,
				   struct drbd_state_change, list);
		cb->args[0] = (long)next_state_change;
		cb->args[3] = notifications_for_state_change(next_state_change);
		cb->args[4] = 0;
	}
out:
	return skb->len;
}

int drbd_adm_get_initial_state(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct drbd_resource *resource;
	LIST_HEAD(head);

	if (cb->args[5] >= 1) {
		if (cb->args[5] > 1)
			return get_initial_state(skb, cb);
		if (cb->args[0]) {
			struct drbd_state_change *state_change =
				(struct drbd_state_change *)cb->args[0];

			/* connect list to head */
			list_add(&head, &state_change->list);
			free_state_changes(&head);
		}
		return 0;
	}

	cb->args[5] = 2;  /* number of iterations */
	mutex_lock(&resources_mutex);
	for_each_resource(resource, &drbd_resources) {
		struct drbd_state_change *state_change;

		state_change = remember_state_change(resource, GFP_KERNEL);
		if (!state_change) {
			if (!list_empty(&head))
				free_state_changes(&head);
			mutex_unlock(&resources_mutex);
			return -ENOMEM;
		}
		copy_old_to_new_state_change(state_change);
		list_add_tail(&state_change->list, &head);
		cb->args[5] += notifications_for_state_change(state_change);
	}
	mutex_unlock(&resources_mutex);

	if (!list_empty(&head)) {
		struct drbd_state_change *state_change =
			list_entry(head.next, struct drbd_state_change, list);
		cb->args[0] = (long)state_change;
		cb->args[3] = notifications_for_state_change(state_change);
		list_del(&head);  /* detach list from head */
	}

	cb->args[2] = cb->nlh->nlmsg_seq;
	return get_initial_state(skb, cb);
}

int drbd_adm_forget_peer(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_config_context adm_ctx;
	struct drbd_resource *resource;
	struct drbd_device *device;
	struct forget_peer_parms parms = { };
	enum drbd_state_rv retcode;
	int vnr, peer_node_id, err;

	retcode = drbd_adm_prepare(&adm_ctx, skb, info, DRBD_ADM_NEED_RESOURCE);
	if (!adm_ctx.reply_skb)
		return retcode;

	resource = adm_ctx.resource;

	err = forget_peer_parms_from_attrs(&parms, info);
	if (err) {
		retcode = ERR_MANDATORY_TAG;
		drbd_msg_put_info(adm_ctx.reply_skb, from_attrs_err_to_txt(err));
		goto out_no_adm;
	}

	mutex_lock(&resource->adm_mutex);

	peer_node_id = parms.forget_peer_node_id;
	if (drbd_connection_by_node_id(resource, peer_node_id)) {
		retcode = ERR_NET_CONFIGURED;
		goto out;
	}

	if (peer_node_id < 0 || peer_node_id >= DRBD_NODE_ID_MAX) {
		retcode = ERR_INVALID_PEER_NODE_ID;
		goto out;
	}

	idr_for_each_entry(&resource->devices, device, vnr) {
		struct drbd_peer_md *peer_md;

		if (!get_ldev(device))
			continue;

		peer_md = &device->ldev->md.peers[peer_node_id];
		if (peer_md->bitmap_index == -1) {
			put_ldev(device);
			retcode = ERR_INVALID_PEER_NODE_ID;
			break;
		}

		peer_md->bitmap_uuid = 0;
		peer_md->flags = 0;
		peer_md->bitmap_index = -1;

		drbd_md_sync(device);
		put_ldev(device);
	}
out:
	mutex_unlock(&resource->adm_mutex);
out_no_adm:
	drbd_adm_finish(&adm_ctx, info, (enum drbd_ret_code)retcode);
	return 0;

}
