/* {"version": "5.1-rc7", "commit": "ae0be8de9a53cda3505865c11826d8ff0640237c", "comment": "nla_nest_start was renamed to _noflag, and the original version became a wrapper adding a flag", "author": "Michal Kubecek <mkubecek@suse.cz>", "date": "Fri Apr 26 11:13:06 2019 +0200"} */
#include <net/netlink.h>

int dummy(struct sk_buff *skb, int attrtype)
{
	return nla_nest_start_noflag(skb, attrtype);
}
