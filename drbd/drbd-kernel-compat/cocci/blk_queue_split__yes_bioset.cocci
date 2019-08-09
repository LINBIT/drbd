@@
identifier qu;
expression b;
@@
- blk_queue_split(qu, b)
+ blk_queue_split(qu, b, qu->bio_split)
