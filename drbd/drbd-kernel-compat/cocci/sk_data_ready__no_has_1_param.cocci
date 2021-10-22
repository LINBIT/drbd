@find_callback@
expression s;
identifier callback;
@@
	s->sk_data_ready = callback;

@@
identifier find_callback.callback;
identifier s;
fresh identifier bytes = "bytes";
@@
-callback(struct sock *s)
+callback(struct sock *s, int bytes)
{...}

// The find_callback rule finds the function names that get assigned to
// the sk_data_ready struct field of any struct.
//
// The second rule then adds the additional parameter to those functions.
//
// At the time of writing this, the only affected callback function is
// dtt_control_data_ready() in the file drbd_transport_tcp.c
