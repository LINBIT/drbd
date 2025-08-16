@@
struct bio *b;
@@
// The only case where we really use bio->bi_bdev is when accessing its bd_disk.
// We can trivially change that to use the old bi_disk instead.
b->
- bi_bdev->bd_disk
+ bi_disk

@@
struct bio *b1;
symbol bio;
@@
drbd_bio_add_page(...)
{
<...
- bio_set_dev(b1, bio->bi_bdev)
+ b1->bi_disk = bio->bi_disk
...>
}
