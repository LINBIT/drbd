// When BIO_OP_SHIFT is present, the op is stored in the higher-order bits of
// bi_opf. Hence we need to shift bits around appropriately.

@@
expression _opf;
@@
-_opf & REQ_OP_MASK
+_opf >> BIO_OP_SHIFT

@@
expression e;
@@
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
+
#define peer_req_op(...) (e)

// We want to wrap the wire_flags_to_bio_op call and flags in a combine_opf
// call. Unfortunately we cannot bind all the flags with a single expression,
// presumably because "|" is left-associative. A "comm_assoc" expression of the
// form "x | ..." would match all the flags, but not bind them. However, we
// also want to avoid having to individually bind each flag, since the number
// is likely to change. Instead, temporarily introduce a "&&" operator with
// weaker precedence, so that we can then bind all the flags as a single
// expression.
@ disable comm_assoc @
symbol dpf;
@@
-wire_flags_to_bio_op(dpf) |
+combine_opf(wire_flags_to_bio_op(dpf), 0) &&
...

@ combine_wire_flags @
symbol dpf;
expression flags;
@@
combine_opf(wire_flags_to_bio_op(dpf),
-0
+flags
 )
- && flags

@ script:python depends on !combine_wire_flags @
@@
import sys
print('ERROR: A rule making an essential change was not executed!', file=sys.stderr)
print('ERROR: This would not show up as a compiler error, but would still break DRBD.', file=sys.stderr)
print('ERROR: As a precaution, the build will be aborted here.', file=sys.stderr)
sys.exit(1)

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
