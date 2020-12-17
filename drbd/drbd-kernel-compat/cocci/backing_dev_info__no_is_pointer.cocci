@@
struct request_queue *q;
identifier x;
@@
q->backing_dev_info
- ->
+ .
x

@@
struct backing_dev_info *b;
struct drbd_device *d;
@@
b =
+ &
d->ldev->backing_bdev->bd_disk->queue->backing_dev_info;

@@
struct request_queue *q;
@@
bdi_congested(
+ &
q->backing_dev_info, ...)
