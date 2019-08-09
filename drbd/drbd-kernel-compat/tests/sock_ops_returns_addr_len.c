/* {"version":"4.17", "commit":"9b2c45d479d0"} */
#include <linux/net.h>
int always_getpeername(struct socket *sock, struct sockaddr *addr)
{
	return sock->ops->getname(sock, addr, 2);
}
