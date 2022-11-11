@@
struct socket *so;
unsigned int v;
@@
- tcp_sock_set_keepidle(so->sk, v);
+ kernel_setsockopt(so, SOL_TCP, TCP_KEEPIDLE, (char *)&v, sizeof(v));
