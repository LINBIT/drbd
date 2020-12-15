@@
identifier socket;
symbol true, false;
@@
(
- tcp_sock_set_cork(socket->sk, true);
+ dtt_cork(socket);
|
- tcp_sock_set_cork(socket->sk, false);
+ dtt_uncork(socket);
)

@@
@@
+static void dtt_cork(struct socket *socket)
+{
+       int val = 1;
+       (void) kernel_setsockopt(socket, SOL_TCP, TCP_CORK, (char *)&val, sizeof(val));
+}
+
+static void dtt_uncork(struct socket *socket)
+{
+       int val = 0;
+       (void) kernel_setsockopt(socket, SOL_TCP, TCP_CORK, (char *)&val, sizeof(val));
+}

dtt_init(...)
{ ... }
