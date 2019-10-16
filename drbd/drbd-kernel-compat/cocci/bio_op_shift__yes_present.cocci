// When BIO_OP_SHIFT is present, the op is stored in the higher-order bits of
// bi_opf. Hence we need to shift bits around appropriately.

@@
expression opf;
@@
-opf & REQ_OP_MASK
+opf >> BIO_OP_SHIFT

@@
expression e;
@@
#define peer_req_op(...) (e)

+/* Combines op and op_flags as bio_set_op_attrs and returns the result. */
+static inline unsigned int combine_opf(unsigned int op, unsigned int op_flags)
+{
+	unsigned int opf;
+	if (__builtin_constant_p(op))
+		BUILD_BUG_ON((op) + 0U >= (1U << REQ_OP_BITS));
+	else
+		WARN_ON_ONCE((op) + 0U >= (1U << REQ_OP_BITS));
+	if (__builtin_constant_p(op_flags))
+		BUILD_BUG_ON((op_flags) + 0U >= (1U << BIO_OP_SHIFT));
+	else
+		WARN_ON_ONCE((op_flags) + 0U >= (1U << BIO_OP_SHIFT));
+	opf = (((op) + 0U) << BIO_OP_SHIFT);
+	opf |= (op_flags);
+	return opf;
+}

@@
expression op, flags;
symbol opf;
@@
wire_flags_to_bio(...) {
-unsigned long opf = op | flags;
+unsigned long opf = combine_opf(op, flags);
...
}

@@
struct drbd_peer_request *peer_req;
identifier op;
@@
-peer_req->opf = op;
+peer_req->opf = combine_opf(op, 0);

@@
struct bio *b;
identifier op;
expression op_flags;
@@
-b->bi_opf = op | op_flags;
+bio_set_op_attrs(b, op, op_flags);

@@
struct bio *b;
identifier op;
@@
-b->bi_opf = op;
+bio_set_op_attrs(b, op, 0);
