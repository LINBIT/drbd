@@
struct bio *b;
expression ebdev;
@@
- bio_set_dev(b, ebdev);
+ b->bi_bdev = ebdev;
