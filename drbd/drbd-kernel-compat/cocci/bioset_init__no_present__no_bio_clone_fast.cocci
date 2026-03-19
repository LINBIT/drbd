@@
identifier bs;
expression bio, gfp;
@@
- bio_clone_fast(bio, gfp, &bs)
+ bio_clone(bio, gfp)
