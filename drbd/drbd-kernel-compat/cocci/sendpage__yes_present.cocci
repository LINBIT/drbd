@ find_msg_splice_pages @
@@
 MSG_SPLICE_PAGES

@ dtt_send_bio_rule @
struct drbd_transport *transport;
int err;
expression d_stream, page, offset, len, msg_flags_ex;
identifier msg_flags;
@@
dtt_send_bio(..., unsigned int msg_flags)
{
<...
+ if (msg_flags & MSG_SPLICE_PAGES) {
  err = dtt_send_page(transport, d_stream, page, offset, len,
- msg_flags_ex
+ (msg_flags_ex) & ~MSG_SPLICE_PAGES
  );
+ } else {
+	err = _dtt_send(container_of(transport, struct drbd_tcp_transport, transport),
+	      		container_of(transport, struct drbd_tcp_transport, transport)->stream[d_stream],
+			page_address(page) + offset, len, msg_flags_ex);
+	if (err > 0)
+		err = 0;
+ }
...>
}

@@
struct dtl_transport *dtl_transport;
int err;
expression flow, page, offset, len, msg_flags_ex;
identifier msg_flags;
@@
dtl_send_bio_pages(..., unsigned int msg_flags)
{
<...
+ if (msg_flags & MSG_SPLICE_PAGES) {
  err = _dtl_send_page(dtl_transport, flow, page, offset, len,
- msg_flags_ex
+ (msg_flags_ex) & ~MSG_SPLICE_PAGES
  );
+ } else {
+	err = _dtl_send(dtl_transport, flow,
+	      		page_address(page) + offset, len, msg_flags_ex);
+	if (err > 0)
+		err = 0;
+ }
...>
}


// Rewrite the bvec-based sock_sendmsg() into a sendpage() call. There may be
// other (kvec-based) sock_sendmsg() calls in the same function, e.g. the TLS
// copy path in dtt_send_page(), so match the bvec sequence on its own rather
// than anchoring on surrounding statements. Match the iter direction as a
// metavariable so this rule does not depend on whether the ITER_SOURCE ->
// WRITE rewrite (iter_source__no_present.cocci) has already been applied.
@@
expression page, len, offset, dir;
identifier msg, socket, sent, bvec;
@@
- bvec_set_page(&bvec, page, len, offset);
- iov_iter_bvec(&msg.msg_iter, dir, &bvec, 1, len);
- sent = sock_sendmsg(socket, &msg);
+ sent = socket->ops->sendpage(socket, page, offset, len, msg.msg_flags);

// Drop the bio_vec declaration left unused by the rewrite above.
@@
identifier bvec;
@@
- struct bio_vec bvec;
  ... when != bvec


@ define_msg_splice_pages depends on find_msg_splice_pages || dtt_send_bio_rule @
@@
 #include <...>
+ #define MSG_SPLICE_PAGES 0x8000000
