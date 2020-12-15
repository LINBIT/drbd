@@
struct request_queue *q, b;
@@
blk_stack_limits(&q->limits, &b->limits, 0);
- blk_queue_update_readahead(q);
+ if (q->backing_dev_info->ra_pages !=
+     b->backing_dev_info->ra_pages) {
+	drbd_info(device, "Adjusting my ra_pages to backing device's (%lu -> %lu)\n",
+		q->backing_dev_info->ra_pages,
+		b->backing_dev_info->ra_pages);
+	q->backing_dev_info->ra_pages =
+				b->backing_dev_info->ra_pages;
+ }
