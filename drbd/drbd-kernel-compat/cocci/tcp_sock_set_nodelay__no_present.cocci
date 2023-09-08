@@
identifier socket;
@@
- tcp_sock_set_nodelay(socket->sk);
+ { int val = 1; (void) kernel_setsockopt(socket, SOL_TCP, TCP_NODELAY, (char *)&val, sizeof(val)); }
