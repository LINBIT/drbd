/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Context and outcome of one DRBD netlink configuration command.
 *
 * The command implementations are independent of the wire format: they
 * receive the identity of the object to act on and report back a result
 * code plus a few informational messages. Translating that into the
 * bytes of a particular netlink dialect is the job of the per-dialect
 * pre_doit/post_doit handlers and of the struct drbd_nl_dialect ops
 * below.
 */
#ifndef __DRBD_NL_H
#define __DRBD_NL_H

#include <linux/compiler.h>
#include <linux/drbd_nl_types.h>

struct drbd_device;
struct drbd_resource;
struct drbd_connection;
struct drbd_peer_device;
struct drbd_path;
struct net;
struct netlink_callback;
struct sk_buff;
struct drbd_nl_dialect;

/* per-message cap, same as drbd_msg_sprintf_info()'s reserve */
#define DRBD_ADM_MSG_MAX	256
/*
 * Total info text per request; a strict superset of what the legacy
 * NLMSG_GOODSIZE reply could carry (that is capped at
 * SKB_WITH_OVERHEAD(8192UL) on every page size).
 */
#define DRBD_ADM_MSG_BUF	8192

struct drbd_adm_ctx {
	/* the dialect the request arrived in, and its private request state */
	const struct drbd_nl_dialect *d;
	void *req;

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
};

/* Attribute sets the core overlays onto live data or reads as parameters. */
enum drbd_nl_attr_set {
	DRBD_NL_SET_DISK_CONF,
	DRBD_NL_SET_NET_CONF,
	DRBD_NL_SET_RES_OPTS,
	DRBD_NL_SET_PEER_DEVICE_CONF,
	DRBD_NL_SET_DEVICE_CONF,
	DRBD_NL_SET_SET_ROLE_PARMS,
	DRBD_NL_SET_RESIZE_PARMS,
	DRBD_NL_SET_START_OV_PARMS,
	DRBD_NL_SET_NEW_C_UUID_PARMS,
	DRBD_NL_SET_DISCONNECT_PARMS,
	DRBD_NL_SET_DETACH_PARMS,
	DRBD_NL_SET_INVALIDATE_PARMS,
	DRBD_NL_SET_INVALIDATE_PEER_PARMS,
	DRBD_NL_SET_FORGET_PEER_PARMS,
	DRBD_NL_SET_CONNECT_PARMS,
	DRBD_NL_SET_PATH_PARMS,
	DRBD_NL_SET_RENAME_RESOURCE_PARMS,
	DRBD_NL_SET_SUSPEND_IO_PARMS,
	__DRBD_NL_SET_MAX,
};

/* Fields the core must refuse to change once set. */
enum drbd_adm_field {
	DRBD_ADM_F_DISK_BACKING_DEV,
	DRBD_ADM_F_DISK_META_DEV,
	DRBD_ADM_F_DISK_META_DEV_IDX,
	DRBD_ADM_F_DISK_SIZE,
	DRBD_ADM_F_NET_TRANSPORT_NAME,
	DRBD_ADM_F_NET_LOAD_BALANCE_PATHS,
	DRBD_ADM_F_RES_NODE_ID,
};

struct drbd_nl_dialect {
	const char *name;
	/* Is the attribute set present in the request at all? */
	bool (*has_set)(struct drbd_adm_ctx *ctx, enum drbd_nl_attr_set set);
	/*
	 * Apply the request's attributes of "set" onto "dst" (a struct of
	 * the matching type); attributes absent from the request leave
	 * "dst" untouched. Returns 0, -ENOMSG (required attribute
	 * missing), -EEXIST (invariant change attempted), or -EINVAL.
	 */
	int (*overlay)(struct drbd_adm_ctx *ctx, enum drbd_nl_attr_set set, void *dst);
	/* Did the request carry this invariant field? Logs if it did. */
	bool (*attr_present)(struct drbd_adm_ctx *ctx, enum drbd_adm_field field);
	/* Reply payloads */
	int (*put_timeout_type)(struct drbd_adm_ctx *ctx, enum drbd_timeout_flag type);

	/*
	 * Dump emitters: append one message describing the object to the
	 * dump skb; return 0 or -errno. A "retcode" other than NO_ERROR
	 * describes a failure instead of an object: only the result code
	 * goes on the wire, and the object pointers must not be
	 * dereferenced (they may be NULL or stale).
	 */
	int (*emit_resource)(struct sk_buff *skb, struct netlink_callback *cb,
			     struct drbd_resource *resource,
			     struct resource_info *info,
			     struct resource_statistics *statistics);
	int (*emit_device)(struct sk_buff *skb, struct netlink_callback *cb, int retcode,
			   struct drbd_device *device,
			   struct disk_conf *disk_conf /* NULL if diskless */,
			   struct device_info *info,
			   struct device_statistics *statistics);
	int (*emit_connection)(struct sk_buff *skb, struct netlink_callback *cb, int retcode,
			       struct drbd_resource *resource,
			       struct drbd_connection *connection,
			       struct net_conf *net_conf /* NULL if none */,
			       struct connection_info *info,
			       struct connection_statistics *statistics);
	int (*emit_peer_device)(struct sk_buff *skb, struct netlink_callback *cb, int retcode,
				struct drbd_peer_device *peer_device, unsigned int minor,
				struct peer_device_info *info,
				struct peer_device_statistics *statistics,
				struct peer_device_conf *conf /* NULL if none */);
	int (*emit_path)(struct sk_buff *skb, struct netlink_callback *cb, int retcode,
			 struct drbd_resource *resource, struct drbd_connection *connection,
			 struct drbd_path *path, struct drbd_path_info *info);

	/*
	 * Notification emitters. skb == NULL: allocate a message, build it
	 * and multicast it to the listeners of this dialect. skb != NULL:
	 * this is the initial state replay, append the message to that
	 * dump skb instead. "seq" is the sequence number of the event,
	 * assigned once per event by the core.
	 */
	int (*notify_resource_state)(struct sk_buff *skb, unsigned int seq,
				     struct drbd_resource *resource,
				     struct resource_info *info,
				     struct rename_resource_info *rename_info,
				     enum drbd_notification_type type);
	int (*notify_device_state)(struct sk_buff *skb, unsigned int seq,
				   struct drbd_device *device,
				   struct device_info *info,
				   enum drbd_notification_type type);
	int (*notify_connection_state)(struct sk_buff *skb, unsigned int seq,
				       struct drbd_connection *connection,
				       struct connection_info *info,
				       enum drbd_notification_type type);
	int (*notify_peer_device_state)(struct sk_buff *skb, unsigned int seq,
					struct drbd_peer_device *peer_device,
					struct peer_device_info *info,
					enum drbd_notification_type type);
	int (*notify_path_state)(struct sk_buff *skb, unsigned int seq,
				 struct drbd_connection *connection, struct drbd_path *path,
				 struct drbd_path_info *info,
				 enum drbd_notification_type type);
	int (*notify_helper)(struct sk_buff *skb, unsigned int seq,
			     struct drbd_device *device, struct drbd_connection *connection,
			     const char *name, int status,
			     enum drbd_notification_type type);
	int (*notify_initial_state_done)(struct sk_buff *skb, unsigned int seq);
};

/* Dialects that receive notifications; registered at module init. */
int drbd_nl_register_dialect(const struct drbd_nl_dialect *dialect);

int drbd_nl_legacy_init(void);
void drbd_nl_legacy_exit(void);

static inline int drbd_adm_overlay_disk_conf(struct drbd_adm_ctx *ctx, struct disk_conf *c)
{ return ctx->d->overlay(ctx, DRBD_NL_SET_DISK_CONF, c); }

static inline int drbd_adm_overlay_net_conf(struct drbd_adm_ctx *ctx, struct net_conf *c)
{ return ctx->d->overlay(ctx, DRBD_NL_SET_NET_CONF, c); }

static inline int drbd_adm_overlay_res_opts(struct drbd_adm_ctx *ctx, struct res_opts *c)
{ return ctx->d->overlay(ctx, DRBD_NL_SET_RES_OPTS, c); }

static inline int drbd_adm_overlay_peer_device_conf(struct drbd_adm_ctx *ctx,
						    struct peer_device_conf *c)
{ return ctx->d->overlay(ctx, DRBD_NL_SET_PEER_DEVICE_CONF, c); }

static inline int drbd_adm_overlay_device_conf(struct drbd_adm_ctx *ctx, struct device_conf *c)
{ return ctx->d->overlay(ctx, DRBD_NL_SET_DEVICE_CONF, c); }

static inline int drbd_adm_overlay_set_role_parms(struct drbd_adm_ctx *ctx,
						  struct set_role_parms *c)
{ return ctx->d->overlay(ctx, DRBD_NL_SET_SET_ROLE_PARMS, c); }

static inline int drbd_adm_overlay_resize_parms(struct drbd_adm_ctx *ctx, struct resize_parms *c)
{ return ctx->d->overlay(ctx, DRBD_NL_SET_RESIZE_PARMS, c); }

static inline int drbd_adm_overlay_start_ov_parms(struct drbd_adm_ctx *ctx,
						  struct start_ov_parms *c)
{ return ctx->d->overlay(ctx, DRBD_NL_SET_START_OV_PARMS, c); }

static inline int drbd_adm_overlay_new_c_uuid_parms(struct drbd_adm_ctx *ctx,
						    struct new_c_uuid_parms *c)
{ return ctx->d->overlay(ctx, DRBD_NL_SET_NEW_C_UUID_PARMS, c); }

static inline int drbd_adm_overlay_disconnect_parms(struct drbd_adm_ctx *ctx,
						    struct disconnect_parms *c)
{ return ctx->d->overlay(ctx, DRBD_NL_SET_DISCONNECT_PARMS, c); }

static inline int drbd_adm_overlay_detach_parms(struct drbd_adm_ctx *ctx, struct detach_parms *c)
{ return ctx->d->overlay(ctx, DRBD_NL_SET_DETACH_PARMS, c); }

static inline int drbd_adm_overlay_invalidate_parms(struct drbd_adm_ctx *ctx,
						    struct invalidate_parms *c)
{ return ctx->d->overlay(ctx, DRBD_NL_SET_INVALIDATE_PARMS, c); }

static inline int drbd_adm_overlay_invalidate_peer_parms(struct drbd_adm_ctx *ctx,
							 struct invalidate_peer_parms *c)
{ return ctx->d->overlay(ctx, DRBD_NL_SET_INVALIDATE_PEER_PARMS, c); }

static inline int drbd_adm_overlay_forget_peer_parms(struct drbd_adm_ctx *ctx,
						     struct forget_peer_parms *c)
{ return ctx->d->overlay(ctx, DRBD_NL_SET_FORGET_PEER_PARMS, c); }

static inline int drbd_adm_overlay_connect_parms(struct drbd_adm_ctx *ctx,
						 struct connect_parms *c)
{ return ctx->d->overlay(ctx, DRBD_NL_SET_CONNECT_PARMS, c); }

static inline int drbd_adm_overlay_path_parms(struct drbd_adm_ctx *ctx, struct path_parms *c)
{ return ctx->d->overlay(ctx, DRBD_NL_SET_PATH_PARMS, c); }

static inline int drbd_adm_overlay_rename_resource_parms(struct drbd_adm_ctx *ctx,
							 struct rename_resource_parms *c)
{ return ctx->d->overlay(ctx, DRBD_NL_SET_RENAME_RESOURCE_PARMS, c); }

static inline int drbd_adm_overlay_suspend_io_parms(struct drbd_adm_ctx *ctx,
						    struct suspend_io_parms *c)
{ return ctx->d->overlay(ctx, DRBD_NL_SET_SUSPEND_IO_PARMS, c); }

__printf(2, 3) void drbd_adm_msg(struct drbd_adm_ctx *ctx, const char *fmt, ...);

/* Flags for drbd_adm_ctx_resolve() */
#define DRBD_ADM_NEED_MINOR        (1 << 0)
#define DRBD_ADM_NEED_RESOURCE     (1 << 1)
#define DRBD_ADM_NEED_CONNECTION   (1 << 2)
#define DRBD_ADM_NEED_PEER_DEVICE  (1 << 3)
#define DRBD_ADM_NEED_PEER_NODE    (1 << 4)
#define DRBD_ADM_IGNORE_VERSION    (1 << 5)

int drbd_adm_ctx_resolve(struct drbd_adm_ctx *ctx, unsigned int flags);
void drbd_adm_ctx_release(struct drbd_adm_ctx *ctx);

/* The netlink commands; each reports its outcome through ctx->result. */
int drbd_adm_primary(struct drbd_adm_ctx *ctx);
int drbd_adm_secondary(struct drbd_adm_ctx *ctx);
int drbd_adm_disk_opts(struct drbd_adm_ctx *ctx);
int drbd_adm_attach(struct drbd_adm_ctx *ctx);
int drbd_adm_detach(struct drbd_adm_ctx *ctx);
int drbd_adm_net_opts(struct drbd_adm_ctx *ctx);
int drbd_adm_peer_device_opts(struct drbd_adm_ctx *ctx);
int drbd_adm_connect(struct drbd_adm_ctx *ctx);
int drbd_adm_new_peer(struct drbd_adm_ctx *ctx);
int drbd_adm_new_path(struct drbd_adm_ctx *ctx);
int drbd_adm_del_path(struct drbd_adm_ctx *ctx);
int drbd_adm_disconnect(struct drbd_adm_ctx *ctx);
int drbd_adm_del_peer(struct drbd_adm_ctx *ctx);
int drbd_adm_resize(struct drbd_adm_ctx *ctx);
int drbd_adm_resource_opts(struct drbd_adm_ctx *ctx);
int drbd_adm_invalidate(struct drbd_adm_ctx *ctx);
int drbd_adm_invalidate_peer(struct drbd_adm_ctx *ctx);
int drbd_adm_pause_sync(struct drbd_adm_ctx *ctx);
int drbd_adm_resume_sync(struct drbd_adm_ctx *ctx);
int drbd_adm_suspend_io(struct drbd_adm_ctx *ctx);
int drbd_adm_resume_io(struct drbd_adm_ctx *ctx);
int drbd_adm_outdate(struct drbd_adm_ctx *ctx);
int drbd_adm_get_timeout_type(struct drbd_adm_ctx *ctx);
int drbd_adm_start_ov(struct drbd_adm_ctx *ctx);
int drbd_adm_new_c_uuid(struct drbd_adm_ctx *ctx);
int drbd_adm_new_resource(struct drbd_adm_ctx *ctx);
int drbd_adm_new_minor(struct drbd_adm_ctx *ctx);
int drbd_adm_del_minor(struct drbd_adm_ctx *ctx);
int drbd_adm_down(struct drbd_adm_ctx *ctx);
int drbd_adm_del_resource(struct drbd_adm_ctx *ctx);
int drbd_adm_forget_peer(struct drbd_adm_ctx *ctx);
int drbd_adm_rename_resource(struct drbd_adm_ctx *ctx);

/*
 * The dumps. The core walks the objects and keeps its cursor in
 * cb->args[]; the dialect turns each object into a message. The
 * optional resource-name filter is resolved by the dialect before it
 * calls in: cb->args[0] then holds that resource with a reference
 * (dropped again by the matching _done callback).
 */
enum { DRBD_DUMP_SINGLE_RESOURCE, DRBD_DUMP_ITERATE_RESOURCES };

int drbd_dump_resources(struct sk_buff *skb, struct netlink_callback *cb,
			const struct drbd_nl_dialect *dialect);
int drbd_dump_devices(struct sk_buff *skb, struct netlink_callback *cb,
		      const struct drbd_nl_dialect *dialect);
int drbd_dump_devices_done(struct netlink_callback *cb);
int drbd_dump_connections(struct sk_buff *skb, struct netlink_callback *cb,
			  const struct drbd_nl_dialect *dialect);
int drbd_dump_connections_done(struct netlink_callback *cb);
int drbd_dump_peer_devices(struct sk_buff *skb, struct netlink_callback *cb,
			   const struct drbd_nl_dialect *dialect);
int drbd_dump_peer_devices_done(struct netlink_callback *cb);
int drbd_dump_paths(struct sk_buff *skb, struct netlink_callback *cb,
		    const struct drbd_nl_dialect *dialect);
int drbd_dump_paths_done(struct netlink_callback *cb);
int drbd_dump_initial_state(struct sk_buff *skb, struct netlink_callback *cb,
			    const struct drbd_nl_dialect *dialect, unsigned int seq);
int drbd_dump_initial_state_done(struct netlink_callback *cb);

/* Statistics of a live object, for the dumps and for the notifications. */
void resource_to_statistics(struct resource_statistics *s, struct drbd_resource *resource);
void device_to_statistics(struct device_statistics *s, struct drbd_device *device);
void connection_to_statistics(struct connection_statistics *s,
			      struct drbd_connection *connection);
void peer_device_to_statistics(struct peer_device_statistics *s,
			       struct drbd_peer_device *peer_device);

/*
 * Notifications. With "dialect" NULL the event is announced to every
 * registered dialect under a freshly drawn sequence number; that is what
 * the notify_*_state() wrappers in drbd_int.h do. A non-NULL dialect
 * (and then always a non-NULL skb) is the initial state replay into the
 * dump skb of that one dialect.
 */
int drbd_notify_resource_state(struct sk_buff *skb, unsigned int seq,
			       const struct drbd_nl_dialect *dialect,
			       struct drbd_resource *resource,
			       struct resource_info *resource_info,
			       struct rename_resource_info *rename_resource_info,
			       enum drbd_notification_type type);
int drbd_notify_device_state(struct sk_buff *skb, unsigned int seq,
			     const struct drbd_nl_dialect *dialect,
			     struct drbd_device *device,
			     struct device_info *device_info,
			     enum drbd_notification_type type);
int drbd_notify_connection_state(struct sk_buff *skb, unsigned int seq,
				 const struct drbd_nl_dialect *dialect,
				 struct drbd_connection *connection,
				 struct connection_info *connection_info,
				 enum drbd_notification_type type);
int drbd_notify_peer_device_state(struct sk_buff *skb, unsigned int seq,
				  const struct drbd_nl_dialect *dialect,
				  struct drbd_peer_device *peer_device,
				  struct peer_device_info *peer_device_info,
				  enum drbd_notification_type type);

#endif /* __DRBD_NL_H */
