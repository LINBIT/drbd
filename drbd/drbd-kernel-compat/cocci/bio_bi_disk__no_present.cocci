@@
struct bio *b;
@@
-b->bi_disk->private_data
+b->bi_bdev->bd_disk->private_data
