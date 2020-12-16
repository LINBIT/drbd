// drbd_int.h
@@
identifier d;
@@
int drbd_queue_order_type(struct drbd_device *d) { ... }

+static inline void drbd_blk_run_queue(struct request_queue *q)
+{
+if (q && q->unplug_fn)
+	q->unplug_fn(q);
+
+}
+
+static inline void drbd_kick_lo(struct drbd_device *device)
+{
+	if (get_ldev(device)) {
+		drbd_blk_run_queue(bdev_get_queue(device->ldev->backing_bdev));
+		put_ldev(device);
+	}
+}

// drbd_bitmap.c
@ add_blk_run_queue @
identifier dev;
@@
bm_rw_range(struct drbd_device *dev, ...)
{
<...
if (!atomic_dec_and_test(...)) {
+	drbd_blk_run_queue(bdev_get_queue(dev->ldev->md_bdev));
	wait_until_done_or_force_detached(...);
} else {
...
}
...>
}

// drbd_main.c
@@
identifier d;
@@
void drbd_queue_unplug(struct drbd_device *d) { ... }

+static void drbd_unplug_fn(struct request_queue *q)
+{
+	struct drbd_device *device = q->queuedata;
+	struct drbd_resource *resource = device->resource;
+
+	/* unplug FIRST */
+	/* note: q->queue_lock == resource->req_lock */
+	spin_lock_irq(&resource->req_lock);
+	blk_remove_plug(q);
+
+	/* only if connected */
+	drbd_queue_unplug(device);
+	spin_unlock_irq(&resource->req_lock);
+
+	drbd_kick_lo(device);
+}

@ add_unplug_fn @
symbol true;
identifier q, resource;
@@
drbd_create_device(...)
{
...
struct drbd_resource *resource = ...;
...
struct request_queue *q;
<...
blk_queue_write_cache(q, true, true);
+q->queue_lock = &resource->req_lock; /* needed since we use */
+/* plugging on a queue, that actually has no requests! */
+q->unplug_fn = drbd_unplug_fn;
...>
}

// drbd_receiver.c
@@
identifier pd, s;
iterator name idr_for_each_entry;
@@
void rs_sectors_came_in(struct drbd_peer_device *pd, int s) { ... }

+/* kick lower level device, if we have more than (arbitrary number)
+ * reference counts on it, which typically are locally submitted io
+ * requests.  don't use unacked_cnt, so we speed up proto A and B, too. */
+static void maybe_kick_lo(struct drbd_device *device)
+{
+	struct disk_conf *dc;
+	unsigned int watermark = 1000000;
+
+	if (get_ldev(device)) {
+		rcu_read_lock();
+		dc = rcu_dereference(device->ldev->disk_conf);
+		if (dc)
+			min_not_zero(dc->unplug_watermark, watermark);
+		rcu_read_unlock();
+
+		if (atomic_read(&device->local_cnt) >= watermark)
+			drbd_kick_lo(device);
+		put_ldev(device);
+	}
+}
+
+static void conn_maybe_kick_lo(struct drbd_connection *connection)
+{
+	struct drbd_resource *resource = connection->resource;
+	struct drbd_device *device;
+	int vnr;
+
+	rcu_read_lock();
+	idr_for_each_entry(&resource->devices, device, vnr)
+		maybe_kick_lo(device);
+	rcu_read_unlock();
+}

@ add_maybe_kick_alloc_pages @
identifier trans, num, gfp, conn;
@@
drbd_alloc_pages(struct drbd_transport *trans, unsigned int num, gfp_t gfp)
{
struct drbd_connection *conn = ...;
<...
	prepare_to_wait(...);
+	conn_maybe_kick_lo(conn);
	drbd_reclaim_net_peer_reqs(conn);
...>
}

@ rewrite_unplug_all @
identifier conn;
iterator name idr_for_each_entry;
@@
void drbd_unplug_all_devices(struct drbd_connection *conn)
{
-...
+	struct drbd_resource *resource = connection->resource;
+	struct drbd_device *device;
+	int vnr;
+
+	rcu_read_lock();
+	idr_for_each_entry(&resource->devices, device, vnr) {
+		kref_get(&device->kref);
+		rcu_read_unlock();
+		drbd_kick_lo(device);
+		kref_put(&device->kref, drbd_destroy_device);
+		rcu_read_lock();
+	}
+	rcu_read_unlock();
}

@ add_maybe_kick_submit_pr @
@@
drbd_submit_peer_request(...)
{
<...
atomic_set(...);
...
+maybe_kick_lo(device);
return 0;
...>
}

// drbd_req.c
@ add_kick_do_submit @
identifier dev, made_progress;
@@
do_submit(...)
{
...
struct drbd_device *dev = ...;
...
bool made_progress;
<...
if (made_progress)
	break;
+ drbd_kick_lo(dev);
schedule();
...>
+ drbd_kick_lo(dev);
}

@ add_plug_send_and_submit @
type T;
identifier x;
identifier dev;
@@
drbd_send_and_submit(struct drbd_device *dev, ...)
{
...
+	struct request_queue *q = dev->vdisk->queue;
	struct drbd_resource *x = ...;
...
+	/* we need to plug ALWAYS since we possibly need to kick lo_dev.
+	 * we plug after submit, so we won't miss an unplug event */
+	spin_lock_irq(q->queue_lock);
+
+	/* XXX the check on !blk_queue_plugged is redundant,
+	 * implicitly checked in blk_plug_device */
+
+	if (!blk_queue_plugged(q)) {
+		blk_plug_device(q);
+		del_timer(&q->unplug_timer);
+		/* unplugging should not happen automatically... */
+	}
+	spin_unlock_irq(q->queue_lock);
+
	if (...)
		complete_master_bio(...);
}

// drbd_sender.c
@ add_kick_resync_finished exists @
identifier dev;
@@
int drbd_resync_finished(...)
{
<+...
struct drbd_device *dev = ...;
...+>
+drbd_kick_lo(dev);
schedule_timeout_interruptible(...);
...
}

// special case for drbd_transport_rdma: we don't want to apply the "subtle
// breakage" logic there
@ rdma_special_case @
identifier x;
@@
static struct drbd_transport_class x = {
	.name = "rdma",
...
};


@ script:python depends on !rdma_special_case &&
			    (!add_maybe_kick_alloc_pages || !rewrite_unplug_all ||
			    !add_maybe_kick_submit_pr ||
			    !add_kick_resync_finished || !add_blk_run_queue ||
			    !add_unplug_fn || !add_kick_do_submit ||
			    !add_plug_send_and_submit) @
@@
import sys
print('ERROR: A rule adding an essential piece of code was not executed!')
print('ERROR: This would not show up as a compiler error, but would still subtly break DRBD.')
print('ERROR: As a precaution, the build will be aborted here.')
sys.exit(1)
