@@
struct request_queue *q;
@@
(
q->limits.max_discard_sectors = 0;
+ blk_queue_flag_clear(QUEUE_FLAG_DISCARD, q);
|
q->limits.max_discard_sectors = ...;
+ blk_queue_flag_set(QUEUE_FLAG_DISCARD, q);
)

@@
struct request_queue *q;
@@
(
blk_queue_discard_granularity(q, 0);
+ blk_queue_flag_clear(QUEUE_FLAG_DISCARD, q);
|
blk_queue_discard_granularity(q, 512);
+ blk_queue_flag_set(QUEUE_FLAG_DISCARD, q);
)

@@
identifier q, device, fn;
@@
+static void fixup_discard_if_not_supported(struct request_queue *q)
+{
+	/* To avoid confusion, if this queue does not support discard, clear
+	 * max_discard_sectors, which is what lsblk -D reports to the user.
+	 * Older kernels got this wrong in "stack limits".
+	 * */
+	if (!blk_queue_discard(q)) {
+		blk_queue_max_discard_sectors(q, 0);
+		blk_queue_discard_granularity(q, 0);
+	}
+}

fn (struct drbd_device *device, ...)
{
...
struct request_queue *q = device->rq_queue;
...
decide_on_discard_support(...);
<+...
blk_stack_limits(...);
...+>
+ fixup_discard_if_not_supported(q);
}
