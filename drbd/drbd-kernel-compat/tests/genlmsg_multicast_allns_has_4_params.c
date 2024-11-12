/* { "version": "v6.12-rc2", "commit": "56440d7ec28d60f8da3bfa09062b3368ff9b16db", "comment": "gfp_t flags argument was removed", "author": "Eric Dumazet <edumazet@google.com>", "date": "Fri Oct 11 17:12:17 2024 +0000" } */

#include <net/genetlink.h>

void foo(void)
{
	struct genl_family *family = NULL;
	struct sk_buff *skb = NULL;
	u32 portid = 0;
	unsigned int group = 0;
	int r;

	r = genlmsg_multicast_allns(family, skb, portid, group);
}
