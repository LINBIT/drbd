@@
struct bio *b;
@@
-(b->bi_opf & REQ_NOUNMAP)
+(false) /* NOUNMAP not supported on this kernel */
