@@
identifier qu;
expression b;
@@
- blk_queue_split(&b)
+ blk_queue_split(b->bi_disk->queue, &b, b->bi_disk->queue->bio_split)
