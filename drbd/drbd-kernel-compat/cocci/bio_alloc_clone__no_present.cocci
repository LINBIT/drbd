@@
expression bdev, bi, gfp, set;
@@
- bio_alloc_clone(bdev, bi, gfp, set)
+ bio_clone_fast(bi, gfp, set)
