// Before Linux upstream commit aeb193ea6cef28e33589de05ef932424f8e19bde
// (which landed with Linux 3.11)
// callers of skb_seq_read() are forced to call skb_abort_seq_read()
// even when consuming all the data because the last call to
// skb_seq_read (the one that returns 0 to indicate the end) fails to
// unmap the last fragment page.

@find_tcp_read_sock@
expression sock;
identifier rd_desc, func;
@@
	tcp_read_sock(sock, &rd_desc, func);

@@
identifier find_tcp_read_sock.func;
identifier seq, consumed;
@@
func(...)
{
	...
	struct skb_seq_state seq;
	...
+	skb_abort_seq_read(&seq);
	return consumed;
}
