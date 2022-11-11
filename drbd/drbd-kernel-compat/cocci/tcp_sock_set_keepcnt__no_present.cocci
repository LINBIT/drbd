@@
struct socket *so;
unsigned int v;
@@
- tcp_sock_set_keepcnt(so->sk, v);
+ kernel_setsockopt(so, SOL_TCP, TCP_KEEPCNT, (char *)&v, sizeof(v));


@@
struct socket *so;
unsigned int v;
@@
- tcp_sock_set_keepintvl(so->sk, v);
+ kernel_setsockopt(so, SOL_TCP, TCP_KEEPINTVL, (char *)&v, sizeof(v));
