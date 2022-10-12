// Adding stuff back in that was removed upstream is always tricky. Especially
// in this case, a lot of semantics get lost that are not really easy to
// replicate automatically.
// Fortunally, this patch only applies to kernels <=3.10, so this does not need
// to be super "robust" because we probably won't be keeping support for these
// kernels for long anyway.
// With that in mind, this patch just hard codes some locations where the
// queue_discard_zeroes_data information was needed.
@@
identifier dev;
@@
can_do_reliable_discards(struct drbd_device *dev)
{
	...
	if (...) { ... }
+
+	if (queue_discard_zeroes_data(bdev_get_queue(dev->ldev->backing_bdev)))
+		return true;
	...
}

// These next two hunks are for drbd_send_sizes()
@@
identifier p, x, dc, dev;
type T;
symbol queue_discard_zeroes_data;
@@
	...
	struct drbd_device *dev = ...;
	<...
	T x;
+	bool discard_zeroes_if_aligned;
	...
	rcu_read_lock();
	...
	dc = rcu_dereference(dev->ldev->disk_conf);
	...
+	discard_zeroes_if_aligned = dc->discard_zeroes_if_aligned;
	rcu_read_unlock();
	...
	p->qlim->discard_enabled = ...;
+	p->qlim->discard_zeroes_data = discard_zeroes_if_aligned || queue_discard_zeroes_data(q);
	...>

@@
identifier p;
@@
	p->qlim->discard_enabled = 0;
+	p->qlim->discard_zeroes_data = 0;

// And for sanitize_disk_conf()
@@
identifier bdev;
@@
struct block_device *bdev = ...;
+ struct request_queue *q = bdev_get_queue(bdev);
...
if (!bdev_max_discard_sectors(bdev)
+	|| (!queue_discard_zeroes_data(q) && !disk_conf->discard_zeroes_if_aligned)
 ) { ... }
