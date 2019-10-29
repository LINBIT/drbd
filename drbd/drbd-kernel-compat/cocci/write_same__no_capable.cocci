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
expression op;
@@
(
- (op == REQ_OP_WRITE_SAME)
+ (false) /* WRITE_SAME not supported on this kernel */
|
- (op != REQ_OP_WRITE_SAME)
+ (true) /* WRITE_SAME not supported on this kernel */
)

@@
expression e;
@@
-if (e)
-	return REQ_OP_WRITE_SAME;
+WARN_ON_ONCE(e); /* WRITE_SAME not supported on this kernel */
