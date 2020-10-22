@@
iterator name for_each_peer_device_rcu;
@@
drbd_cleanup(...)
{ ... }

+ /**
+  * drbd_congested() - Callback for the flusher thread
+  * @congested_data:	User data
+  * @bdi_bits:		Bits the BDI flusher thread is currently interested in
+  *
+  * Returns 1<<WB_async_congested and/or 1<<WB_sync_congested if we are congested.
+  */
+ static int drbd_congested(void *congested_data, int bdi_bits)
+ {
+ 	struct drbd_device *device = congested_data;
+ 	struct request_queue *q;
+ 	int r = 0;
+
+ 	if (!may_inc_ap_bio(device)) {
+ 		/* DRBD has frozen IO */
+ 		r = bdi_bits;
+ 		goto out;
+ 	}
+
+ 	if (test_bit(CALLBACK_PENDING, &device->resource->flags)) {
+ 		r |= (1 << WB_async_congested);
+ 		/* Without good local data, we would need to read from remote,
+ 		 * and that would need the worker thread as well, which is
+ 		 * currently blocked waiting for that usermode helper to
+ 		 * finish.
+ 		 */
+ 		if (!get_ldev_if_state(device, D_UP_TO_DATE))
+ 			r |= (1 << WB_sync_congested);
+ 		else
+ 			put_ldev(device);
+ 		r &= bdi_bits;
+ 		goto out;
+ 	}
+
+ 	if (get_ldev(device)) {
+ 		q = bdev_get_queue(device->ldev->backing_bdev);
+ 		r = bdi_congested(q->backing_dev_info, bdi_bits);
+ 		put_ldev(device);
+ 	}
+
+ 	if (bdi_bits & (1 << WB_async_congested)) {
+ 		struct drbd_peer_device *peer_device;
+
+ 		rcu_read_lock();
+ 		for_each_peer_device_rcu(peer_device, device) {
+ 			if (test_bit(NET_CONGESTED, &peer_device->connection->transport.flags)) {
+ 				r |= (1 << WB_async_congested);
+ 				break;
+ 			}
+ 		}
+ 		rcu_read_unlock();
+ 	}
+
+ out:
+ 	return r;
+ }

@@
identifier dev;
@@
drbd_create_device(...)
{
...
	struct drbd_device *dev;
...
+	q->backing_dev_info->congested_fn = drbd_congested;
+	q->backing_dev_info->congested_data = dev;
	blk_queue_write_cache(...);
...
}
