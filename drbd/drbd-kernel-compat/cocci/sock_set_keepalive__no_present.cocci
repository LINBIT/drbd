@@
struct socket *so;
@@
- sock_set_keepalive(so->sk);
+{
+ int one = 1;
+ kernel_setsockopt(so, SOL_SOCKET, SO_KEEPALIVE, (char *)&one, sizeof(one));
+}
