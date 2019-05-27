@@
identifier find_struct_bio_set.bs;
expression bio, gfp;
@@
bio_clone_fast(bio, gfp,
- &bs
+ bs
 )
