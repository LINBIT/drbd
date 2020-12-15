@@
identifier ws;
@@
+extern int drbd_merge_bvec(struct request_queue *, struct bvec_merge_data *, struct bio_vec *);
extern void do_submit(struct work_struct *ws);

@@
@@
+/* This is called by bio_add_page().
+ *
+ * q->max_hw_sectors and other global limits are already enforced there.
+ *
+ * We need to call down to our lower level device,
+ * in case it has special restrictions.
+ *
+ * As long as the BIO is empty we have to allow at least one bvec,
+ * regardless of size and offset, so no need to ask lower levels.
+ */
+int drbd_merge_bvec(struct request_queue *q,
+		struct bvec_merge_data *bvm,
+		struct bio_vec *bvec)
+{
+	struct drbd_device *device = (struct drbd_device *) q->queuedata;
+	unsigned int bio_size = bvm->bi_size;
+	int limit = DRBD_MAX_BIO_SIZE;
+	int backing_limit;
+
+	if (bio_size && get_ldev(device)) {
+		unsigned int max_hw_sectors = queue_max_hw_sectors(q);
+		struct request_queue * const b =
+			device->ldev->backing_bdev->bd_disk->queue;
+		if (b->merge_bvec_fn) {
+			bvm->bi_bdev = device->ldev->backing_bdev;
+			backing_limit = b->merge_bvec_fn(b, bvm, bvec);
+			limit = min(limit, backing_limit);
+		}
+		put_ldev(device);
+		if ((limit >> 9) > max_hw_sectors)
+			limit = max_hw_sectors << 9;
+	}
+	return limit;
+}

do_submit(...)
{ ... }

@@
identifier x;
@@
{
...
blk_queue_write_cache(x, ...);
+ blk_queue_merge_bvec(x, drbd_merge_bvec);
...
}
