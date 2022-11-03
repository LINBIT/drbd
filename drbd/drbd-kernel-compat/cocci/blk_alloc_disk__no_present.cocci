@@
expression node;
fresh identifier q = "" ## "q";
identifier f, disk, device;
symbol out_no_io_page, out_no_disk;
@@
f(...) {
...
struct drbd_device *device;
+ struct request_queue *q;
...
- disk = blk_alloc_disk(node);
+ q = blk_alloc_queue(node);
+ if (!q) {
+	goto out_no_q;
+ }
+ device->rq_queue = q;
+ disk = alloc_disk(1);
...
device->vdisk = disk;
- device->rq_queue = disk->queue;
...
- disk->minors = 1;
+ disk->queue = q;
... when exists
out_no_io_page:
(
-	blk_cleanup_disk(disk);
+	put_disk(disk);
|
...
)
out_no_disk:
+	blk_cleanup_queue(q);
+ out_no_q:
...
}

@@
identifier f, device;
@@
f(...) {
...
struct drbd_device *device;
...
- blk_cleanup_disk(device->vdisk);
+ put_disk(device->vdisk);
+ blk_cleanup_queue(device->rq_queue);
...
}
