// NOTE this actually encompasses three patches:
// 1122c0c1 block: move cache control settings out of queue->flags
// bd4a633b block: move the nonrot flag to queue_limits
// 1a02f3a7 block: move the stable_writes flag to queue_limits
//
// They add "BLK_FEAT_WRITE_CACHE | BLK_FEAT_FUA", "BLK_FEAT_ROTATIONAL", and
// "BLK_FEAT_STABLE_WRITES", respectively.
// Since these commits are all from the same series, just patch them together.
@@
expression e;
struct gendisk *disk;
identifier lim;
@@
-struct queue_limits lim = {
-	.features = e,
-};
...
blk_alloc_disk(
-	&lim
+	NULL
	, ...)
...
disk->private_data = ...;
+ blk_queue_flag_set(QUEUE_FLAG_STABLE_WRITES, disk->queue);
+ blk_queue_write_cache(disk->queue, true, true);
