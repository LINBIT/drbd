@@ identifier timer_fn, drbd_struct, object, timer, t; @@
void
-timer_fn(struct timer_list *t)
+timer_fn(unsigned long data)
{
-	struct drbd_struct *object = from_timer(object, t, timer);
+	struct drbd_struct *object = (struct drbd_struct *) data;
	...
}


@@ identifier timer, timer_fn, object; @@
-	timer_setup(&object->timer, timer_fn, 0);
+	setup_timer(&object->timer, timer_fn, (unsigned long)object);


@@
//local idexpression struct drbd_peer_device *peer_device;
@@
-	resync_timer_fn(&peer_device->resync_timer)
+	resync_timer_fn((unsigned long) peer_device)
