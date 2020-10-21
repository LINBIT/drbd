@@
identifier socket;
@@
- tcp_sock_set_nodelay(socket->sk);
+ dtt_nodelay(socket);

@@
@@
+static void dtt_nodelay(struct socket *socket)
+{
+       int val = 1;
+       (void) kernel_setsockopt(socket, SOL_TCP, TCP_NODELAY, (char *)&val, sizeof(val));
+}

dtt_init(...)
{ ... }
