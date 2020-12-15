@@
expression q;
@@
- blk_queue_flag_set(QUEUE_FLAG_STABLE_WRITES, q);
+ drbd_warn(device, "No kernel support for stable writes");
