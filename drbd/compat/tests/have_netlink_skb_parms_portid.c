#include <linux/netlink.h>

void dummy(void)
{
	struct netlink_skb_parms nsp;
	nsp.portid = 0;
}
