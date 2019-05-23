@find_sock_ops_getname@
struct socket *sock;
struct sockaddr *uaddr;
int peer;
@@
 sock->ops->getname(sock, uaddr, peer);

@script:python gen_sock_ops_getname@
sock << find_sock_ops_getname.sock;
uaddr << find_sock_ops_getname.uaddr;
peer << find_sock_ops_getname.peer;
x;
@@
coccinelle.x = "({ int len = 0; " + sock + "->ops->getname("      \
		+ "{0}, {1}, &len, {2}".format(sock, uaddr, peer) \
		+ ") ?: len; })"                                  \

@@
struct socket *find_sock_ops_getname.sock;
struct sockaddr *find_sock_ops_getname.uaddr;
int find_sock_ops_getname.peer;
identifier gen_sock_ops_getname.x;
@@
- sock->ops->getname(sock, uaddr, peer)
+ x
