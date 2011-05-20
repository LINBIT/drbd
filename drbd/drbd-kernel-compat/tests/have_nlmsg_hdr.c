#include <linux/skbuff.h>
#include <linux/netlink.h>

void f(void)
{
	struct sk_buff *skb = NULL;
	struct nlmsghdr *hdr = nlmsg_hdr(skb);
}
