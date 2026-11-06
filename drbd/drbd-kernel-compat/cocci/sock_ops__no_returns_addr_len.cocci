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

@ has_call @
identifier fn;
struct socket *sock;
struct sockaddr *uaddr;
int peer;
@@
fn(...)
{
<+...
sock->ops->getname(sock, uaddr, peer);
...+>
}

@@
identifier has_call.fn;
@@
fn(...)
{
+int ___addr_len;
...
}

@ depends on has_call @
struct socket *sock;
struct sockaddr *uaddr;
int peer;
@@
- sock->ops->getname(sock, uaddr, peer);
+ sock->ops->getname(sock, uaddr, &___addr_len, peer);
