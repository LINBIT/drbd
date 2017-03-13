#include <net/genetlink.h>

void test(void)
{
	struct genl_family family = { };
	struct sk_buff *skb = NULL;

	genlmsg_multicast(&family, skb, 0, 0, GFP_KERNEL);
}
