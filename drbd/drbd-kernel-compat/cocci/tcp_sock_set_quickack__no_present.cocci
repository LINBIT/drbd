@@
identifier socket;
@@
- tcp_sock_set_quickack(socket->sk, 2);
+ { int val = 2; (void) kernel_setsockopt(socket, SOL_TCP, TCP_QUICKACK, (char *)&val, sizeof(val)); }
