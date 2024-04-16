@@
@@
struct drbd_backing_dev {
...
- struct bdev_handle *backing_bdev_handle;
...
- struct bdev_handle *md_bdev_handle;
...
}

@@
identifier handle;
@@
static void close_backing_dev(...,
-	struct bdev_handle *handle
+	struct block_device *bdev, void *holder
	, ...
 )
{
<...
(
- handle->bdev
+ bdev
|
- bdev_release(handle)
+ blkdev_put(bdev, holder)
|
- handle
+ bdev
)
...>
} 

@@
identifier device;
struct bdev_handle *handle;
identifier err;
identifier new_disk_conf;
@@
// special case: when linking the meta_dev, we want to pass meta_claim_ptr to close instead of device
err = link_backing_dev(..., new_disk_conf->meta_dev, ...);
if (err) {
	...
	close_backing_dev(device,
-		handle
+		bdev, meta_claim_ptr
	, ...);
	...
}

@@
identifier ldev;
struct bdev_handle *handle;
identifier device;
@@
// generic close_backing_dev usage
close_backing_dev(device,
(
- ldev->backing_bdev_handle
+ ldev->backing_bdev, device
|
- ldev->md_bdev_handle
+ ldev->md_bdev,
+ ldev->md.meta_dev_idx < 0 ? (void *)device : (void *)drbd_m_holder
|
- handle
+ bdev, device
)
, ...);

@@
identifier handle;
@@
- struct bdev_handle *
+ struct block_device *
open_backing_dev(...)
{
...
- struct bdev_handle *handle = bdev_open_by_path(
+ struct block_device *bdev = blkdev_get_by_path(
...);
<...
(
IS_ERR
|
PTR_ERR
)
 (
- handle
+ bdev
 )
...>
return
- handle
+ bdev
;
}

@@
identifier handle;
identifier err;
@@
static int link_backing_dev(...,
-	struct bdev_handle *handle
+	struct block_device *bdev
 )
{
...
int err = bd_link_disk_holder(
-	handle->bdev
+	bdev
	, ...);
if (err) {
-	bdev_release(handle);
	...
}
...
}

@@
identifier device;
expression bd;
identifier handle;
@@
// generic link_backing_dev usage
link_backing_dev(device, bd,
-	handle
+	bdev
 )

@@
identifier handle;
@@
// generic open_backing_dev usage
{
...
- struct bdev_handle *handle;
+ struct block_device *bdev;
<...
(
- handle
+ bdev
= open_backing_dev(...);
|
IS_ERR(
- handle
+ bdev
 )
)
...>
}

@@
struct drbd_backing_dev *nbc;
identifier handle;
@@
(
- nbc->backing_bdev = handle->bdev;
- nbc->backing_bdev_handle = handle;
+ nbc->backing_bdev = bdev;
|
- nbc->md_bdev = handle->bdev;
- nbc->md_bdev_handle = handle;
+ nbc->md_bdev = bdev;
)

@@
identifier handle;
identifier nbc;
@@
// only this one comparison exists in the code, just special-case it instead of implementing the generic case
- handle->bdev != nbc->backing_bdev
+ bdev != nbc->backing_bdev
