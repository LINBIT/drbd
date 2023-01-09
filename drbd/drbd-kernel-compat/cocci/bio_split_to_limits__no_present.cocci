@@
struct bio *b;
@@
- b = bio_split_to_limits(b);
- if (!b)
- 	return;
+ blk_queue_split(&b);
