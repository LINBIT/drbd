@@
identifier socket;
symbol true, false;
@@
(
- tcp_sock_set_cork(socket->sk, true);
+ { int val = 1; (void) kernel_setsockopt(socket, SOL_TCP, TCP_CORK, (char *)&val, sizeof(val)); }
|
- tcp_sock_set_cork(socket->sk, false);
+ { int val = 0; (void) kernel_setsockopt(socket, SOL_TCP, TCP_CORK, (char *)&val, sizeof(val)); }
)
