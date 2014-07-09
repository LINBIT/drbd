#define pr_fmt(fmt) "drbd debugfs: " fmt
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/debugfs.h>
#include <linux/stat.h>
#include <linux/list.h>

#include "drbd_int.h"
#include "drbd_req.h"
#include "drbd_debugfs.h"

static struct dentry *drbd_debugfs_root;
static struct dentry *drbd_debugfs_resources;
static struct dentry *drbd_debugfs_minors;

void drbd_debugfs_resource_add(struct drbd_resource *resource)
{
	struct dentry *dentry;
	if (!drbd_debugfs_resources)
		return;

	dentry = debugfs_create_dir(resource->name, drbd_debugfs_resources);
	if (IS_ERR_OR_NULL(dentry))
		goto fail;
	resource->debugfs_res = dentry;

	dentry = debugfs_create_dir("volumes", resource->debugfs_res);
	if (IS_ERR_OR_NULL(dentry))
		goto fail;
	resource->debugfs_res_volumes = dentry;

	dentry = debugfs_create_dir("connections", resource->debugfs_res);
	if (IS_ERR_OR_NULL(dentry))
		goto fail;
	resource->debugfs_res_connections = dentry;

	return;

fail:
	drbd_debugfs_resource_cleanup(resource);
	drbd_err(resource, "failed to create debugfs dentry\n");
}

void drbd_debugfs_resource_cleanup(struct drbd_resource *resource)
{
	/* it is ok to call debugfs_remove(NULL) */
	debugfs_remove_recursive(resource->debugfs_res);
	resource->debugfs_res = NULL;
	resource->debugfs_res_volumes = NULL;
	resource->debugfs_res_connections = NULL;
}

void drbd_debugfs_connection_add(struct drbd_connection *connection)
{
	struct dentry *conns_dir = connection->resource->debugfs_res_connections;
	char conn_name[SHARED_SECRET_MAX];
	struct dentry *dentry;
	if (!conns_dir)
		return;

	rcu_read_lock();
	strcpy(conn_name, rcu_dereference((connection)->net_conf)->name);
	rcu_read_unlock();

	dentry = debugfs_create_dir(conn_name, conns_dir);
	if (IS_ERR_OR_NULL(dentry))
		goto fail;
	connection->debugfs_conn = dentry;
	return;

fail:
	drbd_debugfs_connection_cleanup(connection);
	drbd_err(connection, "failed to create debugfs dentry\n");
}

void drbd_debugfs_connection_cleanup(struct drbd_connection *connection)
{
	debugfs_remove_recursive(connection->debugfs_conn);
	connection->debugfs_conn = NULL;
}

void drbd_debugfs_device_add(struct drbd_device *device)
{
	struct dentry *vols_dir = device->resource->debugfs_res_volumes;
	char minor_buf[8]; /* MINORMASK, MINORBITS == 20; */
	char vnr_buf[8];   /* volume number vnr is even 16 bit only; */
	char *slink_name = NULL;

	struct dentry *dentry;
	if (!vols_dir || !drbd_debugfs_minors)
		return;

	snprintf(vnr_buf, sizeof(vnr_buf), "%u", device->vnr);
	dentry = debugfs_create_dir(vnr_buf, vols_dir);
	if (IS_ERR_OR_NULL(dentry))
		goto fail;
	device->debugfs_vol = dentry;

	snprintf(minor_buf, sizeof(minor_buf), "%u", device->minor);
	slink_name = kasprintf(GFP_KERNEL, "../resources/%s/volumes/%u",
			device->resource->name, device->vnr);
	if (!slink_name)
		goto fail;
	dentry = debugfs_create_symlink(minor_buf, drbd_debugfs_minors, slink_name);
	if (IS_ERR_OR_NULL(dentry))
		goto fail;
	device->debugfs_minor = dentry;
	kfree(slink_name);
	return;

fail:
	kfree(slink_name);
	drbd_debugfs_device_cleanup(device);
	drbd_err(device, "failed to create debugfs entries\n");
}

void drbd_debugfs_device_cleanup(struct drbd_device *device)
{
	debugfs_remove(device->debugfs_minor);
	debugfs_remove_recursive(device->debugfs_vol);
	device->debugfs_vol = NULL;
	device->debugfs_minor = NULL;
}

void drbd_debugfs_peer_device_add(struct drbd_peer_device *peer_device)
{
	struct dentry *conn_dir = peer_device->connection->debugfs_conn;
	struct dentry *dentry;
	char vnr_buf[8];

	if (!conn_dir)
		return;

	snprintf(vnr_buf, sizeof(vnr_buf), "%u", peer_device->device->vnr);
	dentry = debugfs_create_dir(vnr_buf, conn_dir);
	if (IS_ERR_OR_NULL(dentry))
		goto fail;
	peer_device->debugfs_peer_dev = dentry;
	return;

fail:
	drbd_debugfs_peer_device_cleanup(peer_device);
	drbd_err(peer_device, "failed to create debugfs entries\n");
}

void drbd_debugfs_peer_device_cleanup(struct drbd_peer_device *peer_device)
{
	debugfs_remove_recursive(peer_device->debugfs_peer_dev);
	peer_device->debugfs_peer_dev = NULL;
}

int __init drbd_debugfs_init(void)
{
	struct dentry *dir;

	dir = debugfs_create_dir("drbd", NULL);
	if (IS_ERR_OR_NULL(dir))
		goto fail;
	drbd_debugfs_root = dir;

	dir = debugfs_create_dir("resources", drbd_debugfs_root);
	if (IS_ERR_OR_NULL(dir))
		goto fail;
	drbd_debugfs_resources = dir;
	dir = debugfs_create_dir("minors", drbd_debugfs_root);
	if (IS_ERR_OR_NULL(dir))
		goto fail;
	drbd_debugfs_minors = dir;
	return 0;

fail:
	if (!IS_ERR_OR_NULL(drbd_debugfs_root)) {
		debugfs_remove_recursive(drbd_debugfs_root);
		drbd_debugfs_root = NULL;
		drbd_debugfs_resources = NULL;
		drbd_debugfs_minors = NULL;
	}
	if (dir)
		return PTR_ERR(dir);
	else
		return -EINVAL;
}

/* not __exit, may be indirectly called
 * from the module-load-failure path as well. */
void drbd_debugfs_cleanup(void)
{
	debugfs_remove_recursive(drbd_debugfs_root);
	drbd_debugfs_root = NULL;
	drbd_debugfs_resources = NULL;
	drbd_debugfs_minors = NULL;
}
