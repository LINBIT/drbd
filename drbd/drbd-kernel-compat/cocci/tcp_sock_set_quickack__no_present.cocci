@@
identifier socket;
@@
- tcp_sock_set_quickack(socket->sk, 2);
+ dtt_quickack(socket);

@@
@@
+static void dtt_quickack(struct socket *socket)
+{
+       int val = 2;
+       (void) kernel_setsockopt(socket, SOL_TCP, TCP_QUICKACK, (char *)&val, sizeof(val));
+}

dtt_init(...)
{ ... }
