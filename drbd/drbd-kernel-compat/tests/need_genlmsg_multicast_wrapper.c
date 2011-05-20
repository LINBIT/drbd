#include <net/genetlink.h>

void f(void)
{
	struct sk_buff *skb = NULL;
	int ret;

	ret = genlmsg_multicast(skb, 0, 0);
}
