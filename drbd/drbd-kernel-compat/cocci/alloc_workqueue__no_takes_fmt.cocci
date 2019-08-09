@@
@@
(
-alloc_ordered_workqueue("drbd%u_submit", ...)
+create_singlethread_workqueue("drbd_submit")
|
-alloc_ordered_workqueue("drbd_as_%s", ...)
+create_singlethread_workqueue("drbd_ack_sender")
)
