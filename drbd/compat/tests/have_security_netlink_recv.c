#include <linux/security.h>

int f(void)
{
	struct sk_buff *skb = NULL;
	return security_netlink_recv(skb, CAP_SYS_ADMIN);
}
