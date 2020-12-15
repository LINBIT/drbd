@@
expression q;
@@
- blk_queue_flag_set(QUEUE_FLAG_STABLE_WRITES, q);
+ q->backing_dev_info->capabilities |= BDI_CAP_STABLE_WRITES;
