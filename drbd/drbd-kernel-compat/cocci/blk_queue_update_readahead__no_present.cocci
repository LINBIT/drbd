@@
identifier q, b;
@@
struct request_queue *q;
...
struct request_queue *b;
<...
- blk_queue_update_readahead(q);
+ if (q->backing_dev_info->ra_pages !=
+     b->backing_dev_info->ra_pages) {
+	drbd_info(device, "Adjusting my ra_pages to backing device's (%lu -> %lu)\n",
+		q->backing_dev_info->ra_pages,
+		b->backing_dev_info->ra_pages);
+	q->backing_dev_info->ra_pages =
+				b->backing_dev_info->ra_pages;
+ }
...>