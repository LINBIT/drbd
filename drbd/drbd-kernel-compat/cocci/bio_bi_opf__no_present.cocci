@@
struct bio *b;
@@
-b->bi_opf = REQ_OP_FLUSH | REQ_PREFLUSH;
+submit_bio(WRITE_FLUSH, bio);
<...
-submit_bio(b);
...>

@@
struct bio *b;
symbol op, op_flags, rw;
@@
(
-b->bi_opf = op | op_flags;
+b->bi_rw = rw;
|
-b->bi_opf = op;
+b->bi_rw = rw;
)
<...
-submit_bio(b);
+submit_bio(rw, b);
...>

@@
struct bio *b;
constant flag;
@@
-b->bi_opf & flag
+b->bi_rw & flag

@@
struct bio *b;
@@
-b->bi_opf &=
+b->bi_rw &=
...;
