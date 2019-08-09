#include <linux/netlink.h>

int main(void)
{
	struct sk_buff *skb = NULL;

	int portid = NETLINK_CB(skb).portid;
	return 0;
}
