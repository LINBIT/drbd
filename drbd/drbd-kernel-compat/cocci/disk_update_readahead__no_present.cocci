@@
identifier q;
identifier dev;
type T;
@@
T q = dev->rq_queue;
<...
- disk_update_readahead(dev->vdisk);
+ blk_queue_update_readahead(q);
...>
