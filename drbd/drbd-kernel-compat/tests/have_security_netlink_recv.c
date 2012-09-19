#include <linux/security.h>

/*
int f(void)
{
	struct sk_buff *skb = NULL;
	return security_netlink_recv(skb, CAP_SYS_ADMIN);
}

gcc treats function calls of unkown functions as warning.
Therefore we compile the tests with -Werror=implicit-function-declaration
but on gentoo users tend to disable all warnings system wide!

But the following is a compiler error even on such a gentoo system:
*/

void *p = security_netlink_recv;
