#include <linux/skbuff.h>
#include <linux/netlink.h>

void dummy(void)
{
	static struct netlink_skb_parms p;
	p.dst_groups = 0;
}
