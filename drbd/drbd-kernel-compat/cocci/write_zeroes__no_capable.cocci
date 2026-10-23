@@
identifier device, q;
@@
-fixup_write_zeroes(struct drbd_device *device, struct request_queue *q)
-{
-...
-}

@@
identifier device, q;
@@
-fixup_write_zeroes(device, q);

// The peer may still send P_ZEROES. receive_Data() marks it EE_ZEROOUT,
// which submits it as a zero-out without REQ_OP_WRITE_ZEROES.
@@
expression pd, e;
@@
-D_ASSERT(pd, e == REQ_OP_WRITE_ZEROES);

@@
expression _op;
@@
(
- (_op == REQ_OP_WRITE_ZEROES)
+ (false) /* WRITE_ZEROES not supported on this kernel */
|
- (_op != REQ_OP_WRITE_ZEROES)
+ (true) /* WRITE_ZEROES not supported on this kernel */
)

@@
expression e;
@@
-if (e)
-	return REQ_OP_WRITE_ZEROES;

@@
struct queue_limits lim;
@@
- lim.max_write_zeroes_sectors = ...;
