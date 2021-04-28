@@
struct bio *b;
@@
// The only case where we really use bio->bi_bdev is when accessing its bd_disk.
// We can trivially change that to use the old bi_disk instead.
b->
- bi_bdev->bd_disk
+ bi_disk
