@@
struct bio *b;
expression op, op_flags;
@@
-b->bi_opf = op | op_flags;
+bio_set_op_attrs(b, op, op_flags);

@@
struct bio *b;
symbol op;
@@
-b->bi_opf = op;
+bio_set_op_attrs(b, op, 0);
