#include <net/genetlink.h>

void f(void)
{
	struct sk_buff *skb;

	skb = genlmsg_new(123, GFP_KERNEL);
}
