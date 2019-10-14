@@
struct bio *b;
@@
(
-(b->bi_opf & REQ_NOUNMAP)
+(false) /* NOUNMAP not supported on this kernel */
|
-!(b->bi_opf & REQ_NOUNMAP)
+(true) /* NOUNMAP not supported on this kernel */
)
