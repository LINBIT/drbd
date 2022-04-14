@@
expression q;
identifier x;
@@
q->backing_dev_info
- ->
+ .
x

@@
struct drbd_device *d;
@@
+ &
d->ldev->backing_bdev->bd_disk->queue->backing_dev_info

@@
expression q;
@@
bdi_congested(
+ &
q->backing_dev_info, ...)
