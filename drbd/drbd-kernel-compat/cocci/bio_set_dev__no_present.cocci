@@
struct bio *b;
expression bdev;
@@
- bio_set_dev(b, bdev);
+ b->bi_bdev = bdev;
