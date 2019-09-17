@@
identifier q;
@@
void assign_p_sizes_qlim(..., struct request_queue *q)
{
<...
-!!q->limits.max_write_same_sectors
+0
...>
}

@@
@@
void decide_on_write_same_support(...)
{
-...
+drbd_dbg(device, "This kernel is too old, no WRITE_SAME support.\n");
}

@@
@@
void drbd_issue_peer_wsame(...)
{
-...
+	/* We should have never received this request!  At least not until we
+	 * implement an open-coded write-same equivalent submit loop, and tell
+	 * our peer we were write_same_capable. */
+	drbd_err(device, "received unsupported WRITE_SAME request\n");
+	peer_req->flags |= EE_WAS_ERROR;
+	drbd_endio_write_sec_final(peer_req);
}

@@
expression device, peer_req, flags, fault_type;
@@
drbd_submit_peer_request(device, peer_req
-, REQ_OP_WRITE_SAME, flags
+, (-2) /* WRITE_SAME not supported on this kernel */
, fault_type)

@@
struct bio *b;
@@
(
- (bio_op(b) == REQ_OP_WRITE_SAME)
+ (false) /* WRITE_SAME not supported on this kernel */
|
- (bio_op(b) != REQ_OP_WRITE_SAME)
+ (true) /* WRITE_SAME not supported on this kernel */
)

@@
identifier pd, o;
@@
-D_ASSERT(pd, o == REQ_OP_WRITE_SAME);

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
- o == REQ_OP_WRITE_SAME
+ (false) /* WRITE_SAME not supported on this kernel */
|
- o != REQ_OP_WRITE_SAME
+ (true) /* WRITE_SAME not supported on this kernel */
)
...>
}

@@
@@
-REQ_OP_WRITE_SAME
+(-2) /* WRITE_SAME not supported on this kernel */
