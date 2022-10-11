#ifndef DRBD_STATE_CHANGE_H
#define DRBD_STATE_CHANGE_H

struct drbd_resource_state_change {
	struct drbd_resource *resource;
	enum drbd_role role[2];
	bool susp[2];
	bool susp_nod[2];
	bool susp_uuid[2];
	bool fail_io[2];
};

struct drbd_device_state_change {
	struct drbd_device *device;
	enum drbd_disk_state disk_state[2];
	bool have_quorum[2];
};

struct drbd_connection_state_change {
	struct drbd_connection *connection;
	enum drbd_conn_state cstate[2];
	enum drbd_role peer_role[2];
	bool susp_fen[2];
};

/* exception: stores state, not change.
 * for get_initial_state. */
struct drbd_path_state {
	struct drbd_connection *connection;
	struct drbd_path *path;
	/* not an array,
	 * because it's not an array in struct drbd_path either */
	bool path_established;
};

struct drbd_peer_device_state_change {
	struct drbd_peer_device *peer_device;
	enum drbd_disk_state disk_state[2];
	enum drbd_repl_state repl_state[2];
	bool resync_susp_user[2];
	bool resync_susp_peer[2];
	bool resync_susp_dependency[2];
	bool resync_susp_other_c[2];
	bool resync_active[2];
};

struct drbd_state_change_object_count {
	unsigned int n_devices;
	unsigned int n_connections;
	unsigned int n_paths;
};

struct drbd_state_change {
	struct list_head list;
	unsigned int n_devices;
	unsigned int n_connections;
	unsigned int n_paths;
	struct drbd_resource_state_change resource[1];
	struct drbd_device_state_change *devices;
	struct drbd_connection_state_change *connections;
	struct drbd_peer_device_state_change *peer_devices;
	struct drbd_path_state *paths;
};

extern struct drbd_state_change *remember_state_change(struct drbd_resource *, gfp_t);
extern void copy_old_to_new_state_change(struct drbd_state_change *);
extern void forget_state_change(struct drbd_state_change *);

extern int notify_resource_state_change(struct sk_buff *,
					 unsigned int,
					 struct drbd_state_change *,
					 enum drbd_notification_type type);
extern int notify_connection_state_change(struct sk_buff *,
					   unsigned int,
					   struct drbd_connection_state_change *,
					   enum drbd_notification_type type);
extern int notify_device_state_change(struct sk_buff *,
				       unsigned int,
				       struct drbd_device_state_change *,
				       enum drbd_notification_type type);
extern int notify_peer_device_state_change(struct sk_buff *,
					    unsigned int,
					    struct drbd_peer_device_state_change *,
					    enum drbd_notification_type type);

#endif  /* DRBD_STATE_CHANGE_H */
