#include <drbd_kref_debug.h>

struct kref_debug_class kref_class_resource = {
	"resource", {
		[1] = "kthread",
		[2] = "drbd_adm_prepare()/drbd_adm_finish()",
		[3] = "struct drbd_connection",
		[4] = "struct drbd_device",
		[5] = "struct drbd_state_change",
		[6] = "drbd_adm_dump_connections()",
	}
};

struct kref_debug_class kref_class_connection = {
	"connection", {
		[1] = "kthread",
		[2] = "drbd_adm_prepare()/drbd_adm_finish()",
		[3] = "struct drbd_peer_device",
		[4] = "conn_try_outdate_peer_async()",
		[5] = "__cluster_wide_request()",
		[6] = "change_cluster_wide_state()",
		[7] = "struct drbd_state_change",
		[8] = "target_connection/change_cluster_wide_state()",
		[9] = "resource->twopc_parent",
	}
};

struct kref_debug_class kref_class_device = {
	"device", {
		[1] = "struct drbd_peer_device",
		[2] = "struct drbd_state_change",
	}
};


