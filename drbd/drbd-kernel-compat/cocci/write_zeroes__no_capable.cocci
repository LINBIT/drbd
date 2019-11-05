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

@@
expression op;
@@
(
- (op == REQ_OP_WRITE_ZEROES)
+ (false) /* WRITE_ZEROES not supported on this kernel */
|
- (op != REQ_OP_WRITE_ZEROES)
+ (true) /* WRITE_ZEROES not supported on this kernel */
)

@@
expression e;
@@
-if (e)
-	return REQ_OP_WRITE_ZEROES;
+WARN_ON_ONCE(e); /* WRITE_ZEROES not supported on this kernel */
