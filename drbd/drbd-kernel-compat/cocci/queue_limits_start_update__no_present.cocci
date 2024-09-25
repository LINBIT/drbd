@@
identifier lim;
identifier q;
identifier device;
identifier bdev;
@@
void drbd_reconsider_queue_parameters(struct drbd_device *device, struct drbd_backing_dev *bdev)
{
...
	lim =
-	queue_limits_start_update(q);
+	q->limits;
...
-	if (queue_limits_commit_update(q, &lim)) { ... }
+	q->limits = lim;
+	blk_queue_max_hw_sectors(q, lim.max_hw_sectors);
+	blk_queue_max_discard_sectors(q, lim.max_hw_discard_sectors);
+	if (bdev)
+		disk_update_readahead(device->vdisk);
...
}
