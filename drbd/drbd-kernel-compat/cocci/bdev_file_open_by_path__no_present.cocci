@@
@@
struct drbd_backing_dev {
...
- struct file *backing_bdev_file;
+ struct bdev_handle *backing_bdev_handle;
...
- struct file *f_md_bdev;
+ struct bdev_handle *md_bdev_handle;
...
}

@@
identifier bdev_file;
@@
static void close_backing_dev(...,
-	struct file *bdev_file
+	struct bdev_handle *handle
	, ...
 )
{
<...
(
- file_bdev(bdev_file)
+ handle->bdev
|
- fput(bdev_file)
+ bdev_release(handle)
|
- !bdev_file
+ !handle
)
...>
}

@@
identifier ldev;
struct file *file;
identifier device;
@@
// generic close_backing_dev usage
close_backing_dev(device,
(
- ldev->backing_bdev_file
+ ldev->backing_bdev_handle
|
- ldev->f_md_bdev
+ ldev->md_bdev_handle
|
- file
+ handle
)
, ...);

@@
identifier file;
@@
- struct file *
+ struct bdev_handle *
open_backing_dev(...)
{
...
- struct file *file = bdev_file_open_by_path(
+ struct bdev_handle *handle = bdev_open_by_path(
...);
<...
(
IS_ERR
|
PTR_ERR
)
 (
- file
+ handle
 )
...>
return
- file
+ handle
;
}

@@
identifier file;
identifier err;
@@
static int link_backing_dev(...,
-	struct file *file
+	struct bdev_handle *handle
 )
{
...
int err = bd_link_disk_holder(
-	file_bdev(file)
+	handle->bdev
	, ...);
if (err) {
-	fput(file);
+	bdev_release(handle);
	...
}
...
}

@@
identifier device;
expression bd;
identifier file;
@@
// generic link_backing_dev usage
link_backing_dev(device, bd,
-	file
+	handle
 )

@@
identifier file;
@@
// generic open_backing_dev usage
{
...
- struct file *file;
+ struct bdev_handle *handle;
<+...
(
- file
+ handle
= open_backing_dev(...);
|
IS_ERR(
- file
+ handle
 )
)
...+>
}

@@
struct drbd_backing_dev *nbc;
identifier file;
@@
(
- nbc->backing_bdev = file_bdev(file);
- nbc->backing_bdev_file = file;
+ nbc->backing_bdev = handle->bdev;
+ nbc->backing_bdev_handle = handle;
|
- nbc->md_bdev = file_bdev(file);
- nbc->f_md_bdev = file;
+ nbc->md_bdev = handle->bdev;
+ nbc->md_bdev_handle = handle;
)

@@
identifier file;
identifier nbc;
@@
// only this one comparison exists in the code, just special-case it instead of implementing the generic case
- file_bdev(file) != nbc->backing_bdev
+ handle->bdev != nbc->backing_bdev

