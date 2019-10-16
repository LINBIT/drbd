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
@@
-REQ_OP_WRITE_ZEROES
+(-3) /* WRITE_ZEROES not supported on this kernel */
