#include <net/genetlink.h>

void f(void)
{
	struct sk_buff *skb = NULL;
	struct genl_info *info = NULL;
	int ret = genlmsg_reply(skb, info);
}
