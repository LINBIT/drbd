@@
expression b;
@@
- blk_queue_split(&b)
+ blk_queue_split(b->bi_bdev->bd_disk->queue, &b)
