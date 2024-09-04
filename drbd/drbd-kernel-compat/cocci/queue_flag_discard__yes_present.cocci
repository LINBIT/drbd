@@
struct queue_limits lim;
identifier q;
@@
struct request_queue *q = device->rq_queue;
...
(
lim.max_hw_discard_sectors = 0;
+ blk_queue_flag_clear(QUEUE_FLAG_DISCARD, q);
|
lim.max_hw_discard_sectors = ...;
+ blk_queue_flag_set(QUEUE_FLAG_DISCARD, q);
)

@@
identifier q, device;
@@
+static void fixup_discard_if_not_supported(struct request_queue *q)
+{
+	/* To avoid confusion, if this queue does not support discard, clear
+	 * max_discard_sectors, which is what lsblk -D reports to the user.
+	 * Older kernels got this wrong in "stack limits".
+	 * */
+	if (!blk_queue_discard(q)) {
+		blk_queue_max_discard_sectors(q, 0);
+		q->limits.discard_granularity = 0;
+	}
+}

void drbd_reconsider_queue_parameters(struct drbd_device *device, ...)
{
...
struct request_queue *q = device->rq_queue;
...
+ fixup_discard_if_not_supported(q);
}
