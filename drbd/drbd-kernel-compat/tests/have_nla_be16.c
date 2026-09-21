/* { "version": "v6.2-rc1", "commit": "ecaf75ffd5f5db320d8b1da0198eef5a5ce64a3f", "comment": "netlink: introduce bigendian integer types - NLA_BE16 and NLA_BE32 policy types; distributions backported the split genetlink ops without these, so test for them separately", "author": "Florian Westphal <fw@strlen.de>", "date": "Mon Oct 31 13:34:07 2022 +0100" } */
#include <net/netlink.h>

struct nla_policy p[] = {
	{ .type = NLA_BE16, },
	{ .type = NLA_BE32, },
};
