@@
expression b;
@@
- blk_queue_split(&b)
+ blk_queue_split(b->bi_disk->queue, &b)
