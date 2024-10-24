@@
unsigned int nr_segs;
@@
- bio_max_segs(nr_segs)
+ min(nr_segs, (unsigned int) BIO_MAX_VECS)
