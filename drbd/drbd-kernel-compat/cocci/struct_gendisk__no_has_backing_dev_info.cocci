@@
struct drbd_device *d;
@@
d->ldev->backing_bdev->
- bd_disk->bdi
+ bd_disk->queue->backing_dev_info
