@@
struct socket *sock;
struct sockaddr *uaddr;
int peer;
identifier addr_len;
@@
{
...
int addr_len;
...
- addr_len = sock->ops->getname(sock, uaddr, peer);
+ sock->ops->getname(sock, uaddr, &addr_len, peer);
...
}


@@
struct socket *sock;
struct sockaddr *uaddr;
int peer;
@@
{
+int ___addr_len;
...
- sock->ops->getname(sock, uaddr, peer);
+ sock->ops->getname(sock, uaddr, &___addr_len, peer);
...
}
