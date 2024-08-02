@@
struct drbd_device *device;
@@
int drbd_open(...)
{
...
+	/*
+	 * Older kernels sometimes fail to clear TIF_SIGPENDING when returning
+	 * from drbd_open() with -ERESTARTSYS. The kernel calls into drbd_open()
+	 * with TIF_SIGPENDING still set. recalc_sigpending() clears
+	 * TIF_SIGPENDING if it is no longer accurate.
+	 */
+	if (signal_pending(current)) {
+		spin_lock_irq(&current->sighand->siglock);
+		recalc_sigpending();
+		spin_unlock_irq(&current->sighand->siglock);
+	}
+
	kref_get(&device->kref);
...
}
