/* { "version": "v4.2-rc1", "commit": "0198e09c4bdd7bce00c451c51a86a239c356a315", "comment": "sock_create_kern gained a parameter for the net namespace in which the socket should be created", "author": "David S. Miller <davem@davemloft.net>", "date": "Mon May 11 10:50:19 2015 -0400" } */
#include <linux/net.h>

void foo(void)
{
	int err;
	err = sock_create_kern((struct net *)NULL, 0, 0, 0, (struct socket **)NULL);
}
