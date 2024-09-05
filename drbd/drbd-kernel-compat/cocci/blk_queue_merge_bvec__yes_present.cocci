@ add_drbd_merge_bvec_definition @
identifier ws;
@@
+extern int drbd_merge_bvec(struct request_queue *, struct bvec_merge_data *, struct bio_vec *);
extern void do_submit(struct work_struct *ws);

@ add_drbd_merge_bvec @
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

@ add_blk_queue_merge_bvec @
symbol true;
identifier q, resource, dev;
struct gendisk *disk;
@@
drbd_create_device(...)
{
...
struct drbd_resource *resource = ...;
...
struct request_queue *q;
...
// In the compat implementation of drbd_merge_bvec, which we insert above,
// we have to get the DRBD device the "old" way, via request_queue->queuedata.
// This is because we do not have access to the actual bio in that function,
// only the request_queue.
// So, if we are using that compat implementation, we just redundantly store
// the device in queuedata as well, so that we have access to it in drbd_merge_bvec.
// The "new" way would be to get the device from bio->bi_disk->private_data,
// like in drbd_submit_bio:
//     struct drbd_device *device = bio->bi_disk->private_data;
// This is still valid, since we still store the device in private_data, we just
// also want to store it in queuedata for the compat.
dev->rq_queue = q;
+ q->queuedata = dev;
...
disk->private_data = ...;
+ blk_queue_merge_bvec(q, drbd_merge_bvec);
...
}

@ script:python depends on !(add_drbd_merge_bvec_definition && add_drbd_merge_bvec && add_blk_queue_merge_bvec) @
@@
import sys
print('ERROR: A rule making an essential change was not executed! (blk_queue_merge_bvec)', file=sys.stderr)
print('ERROR: This would not show up as a compiler error, but would still break DRBD.', file=sys.stderr)
print('ERROR: As a precaution, the build will be aborted here.', file=sys.stderr)
sys.exit(1)

