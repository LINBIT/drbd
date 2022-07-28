@@
identifier err;
expression net;
expression family;
identifier type;
identifier proto;
identifier sock;
@@
err = sock_create_kern(
- net,
family, type, proto, &sock);
if (err < 0) { ... }
+ sk_change_net(sock->sk, net);

@@ expression S; @@
- sock_release(S)
+ sk_release_kernel(S->sk)
