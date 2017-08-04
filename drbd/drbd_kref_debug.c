#include <drbd_kref_debug.h>
#include "drbd_int.h"


static void get_resource_name(const struct kref_debug_info *debug_info, char *name)
{
	struct drbd_resource *resource = container_of(debug_info, struct drbd_resource, kref_debug);
	if (resource->name)
		strcpy(name, resource->name);
	else
		strcpy(name, "unnamed");
}

static void get_connection_name(const struct kref_debug_info *debug_info, char *name)
{
	struct drbd_connection *connection = container_of(debug_info, struct drbd_connection, kref_debug);
	struct net_conf *nc;
	const char *resource_n =
		connection->resource && connection->resource->name ? connection->resource->name : "unknown";

	rcu_read_lock();
	nc = rcu_dereference(connection->transport.net_conf);
	sprintf(name, "%s:%s", resource_n , nc ? nc->name : "unnamed");
	rcu_read_unlock();
}

static void get_device_name(const struct kref_debug_info *debug_info, char *name)
{
	struct drbd_device *device = container_of(debug_info, struct drbd_device, kref_debug);
	const char *resource_n =
		device->resource && device->resource->name ? device->resource->name : "unknown";

	sprintf(name, "%s/%d minor-%d", resource_n, device->vnr, device->minor);
}

struct kref_debug_class kref_class_resource = {
	"resource",
	get_resource_name,
	{
		[1] = "kthread",
		[2] = "drbd_adm_prepare()/drbd_adm_finish()",
		[3] = "struct drbd_connection",
		[4] = "struct drbd_device",
		[5] = "struct drbd_state_change",
		[6] = "drbd_adm_dump_connections()",
		[7] = "drbd_adm_dump_devices()",
		[8] = "free",
		[9] = "drbd_adm_dump_peer_devices()",
	}
};

struct kref_debug_class kref_class_connection = {
	"connection",
	get_connection_name,
	{
		[1] = "kthread",
		[2] = "drbd_adm_prepare()/drbd_adm_finish()",
		[3] = "struct drbd_peer_device",
		[4] = "conn_try_outdate_peer_async()",
		[5] = "remember_state_change()forget_state_change()",
		[6] = "change_cluster_wide_state()",
		[7] = "struct drbd_state_change",
		[8] = "target_connection/change_cluster_wide_state()",
		[9] = "resource->twopc_parent",
		[10] = "free",
		[11] = "connect_timer",
		[12] = "receive_peer_dagtag()",
		[13] = "for_each_connection_ref()",
		[14] = "w_update_peers",
		[15] = "for_each_peer_device_ref()",
		[16] = "queue_twopc",
	}
};



struct kref_debug_class kref_class_device = {
	"device",
	get_device_name,
	{
		[1] = "struct drbd_peer_device / free",
		[2] = "struct drbd_state_change",
		[3] = "open / release",
		[4] = "drbd_adm_prepare()/drbd_adm_finish()",
		[5] = "w_update_peers",
		[6] = "drbd_request",
		[7] = "flush_after_epoch",
		[8] = "send_acks_wf",
	}
};


