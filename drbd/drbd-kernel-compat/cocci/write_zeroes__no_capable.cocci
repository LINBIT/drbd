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
struct bio *b;
@@
(
- (bio_op(b) == REQ_OP_WRITE_ZEROES)
+ (false) /* WRITE_ZEROES not supported on this kernel */
|
- (bio_op(b) != REQ_OP_WRITE_ZEROES)
+ (true) /* WRITE_ZEROES not supported on this kernel */
)

@@
identifier pd, o;
@@
-D_ASSERT(pd, o == REQ_OP_WRITE_ZEROES);

@@
expression device, flags, peer_req, fault_type;
@@
drbd_submit_peer_request(device, peer_req
-, REQ_OP_WRITE_ZEROES, flags
+, (-3) /* WRITE_ZEROES not supported on this kernel */
, fault_type)

@ exists @
type T;
identifier o, fn;
expression flags;
struct bio *b;
@@
fn(...) {
<...
(
T o = bio_op(b);
|
o = bio_op(b);
|
o = wire_flags_to_bio_op(flags);
)
...
(
- o == REQ_OP_WRITE_ZEROES
+ (false) /* WRITE_ZEROES not supported on this kernel */
|
- o != REQ_OP_WRITE_ZEROES
+ (true) /* WRITE_ZEROES not supported on this kernel */
)
...>
}

@@
@@
-REQ_OP_WRITE_ZEROES
+(-3) /* WRITE_ZEROES not supported on this kernel */
