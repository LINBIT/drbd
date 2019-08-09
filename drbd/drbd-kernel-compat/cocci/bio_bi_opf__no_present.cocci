// bio->bi_rw was renamed to bio->bi_opf, but that is really just a consequence
// of the larger change: BIO_RW_* was split into REQ_* and REQ_OP_*.
// This means that operations and flags are now separate, and we need to
// somehow patch it back to be unified again.

@@
struct bio *b;
@@
- b->bi_opf
+ b->bi_rw

@@
struct bio *b;
@@
- submit_bio(b)
+ submit_bio(b->bi_rw, b)

@ replace_bio_op @
expression bio;
@@
- bio_op((bio))
+ op_from_rq_bits(bio->bi_rw)
