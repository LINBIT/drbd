@@
struct bio *b;
@@
- b = bio_split_to_limits(b);
+ blk_queue_split(&b);
