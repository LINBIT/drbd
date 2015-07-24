#include <linux/net.h>


/* With commit eeb1bd5 (linux v4.2) a new parameter was inserted in
   first position */

void foo(void)
{
	int err;
	err = sock_create_kern((struct net *)NULL, 0, 0, 0, (struct socket **)NULL);
}
