@@
identifier err, resource, new_name;
@@
void drbd_debugfs_resource_rename(struct drbd_resource *resource, const char *new_name)
{
-	int err;
+	struct dentry *new_d;

-	err = debugfs_change_name(resource->debugfs_res, "%s", new_name);
-	if (err)
+	new_d = debugfs_rename(drbd_debugfs_resources, resource->debugfs_res,
+				drbd_debugfs_resources, new_name);
+	if (IS_ERR(new_d)) {
		drbd_err(resource, ... );
+	} else {
+		resource->debugfs_res = new_d;
+	}
}
