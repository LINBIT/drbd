@@
expression ebdev, bi, gfp, set;
@@
- bio_alloc_clone(ebdev, bi, gfp, set)
+ bio_clone_fast(bi, gfp, set)
