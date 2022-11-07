#include <net/netlink.h>

int dummy(struct sk_buff *skb, int attrtype, u64 value, int padattr)
{
	return nla_put_64bit(skb, attrtype, sizeof(u64), &value, padattr);
}
