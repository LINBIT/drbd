@@
identifier conn;
@@
receive_Data(struct drbd_connection *conn, ...)
{
<+...
+	/* last "fixes" to rw flags.
+	 * Strip off BIO_RW_BARRIER unconditionally,
+	 * it is not supposed to be here anyways.
+	 * (Was FUA or FLUSH on the peer,
+	 * and got translated to BARRIER on this side).
+	 * Note that the epoch handling code below
+	 * may add it again, though.
+	 */
+	peer_req->rw &= ~REQ_HARDBARRIER;
spin_lock(&conn->epoch_lock);
...+>
}

@@
@@
drbd_make_request(...)
{
	...
	unsigned long start_jif;
+
+	/* We never supported BIO_RW_BARRIER.
+	 * We don't need to, anymore, either: starting with kernel 2.6.36,
+	 * we have REQ_FUA and REQ_PREFLUSH, which will be handled transparently
+	 * by the block layer. */
+	if (unlikely(bio->bi_opf & REQ_HARDBARRIER)) {
+		bio->bi_status = BLK_STS_NOTSUPP;
+		bio_endio(bio);
+		return BLK_QC_T_NONE;
+	}
	...
}
