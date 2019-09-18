/* {"version": "5.1-rc7", "commit": "8cb081746c031fb164089322e2336a0bf5b3070c", "comment": "In order to allow for stricter checking in the future, nla_parse_* as we use it is now deprecated", "author": "Johannes Berg <johannes.berg@intel.com>", "date": "Fri Apr 26 14:07:28 2019 +0200"} */
#include <net/netlink.h>

/* NOTE: this will have to be changed when _deprecated eventually goes away.
 * Hopefully by then we won't be using the deprecated version anymore... */

int dummy(struct nlattr **tb, int maxtype, const struct nlattr *head, int len,
	  const struct nla_policy *policy, struct netlink_ext_ack *extack)
{
	return nla_parse_deprecated(tb, maxtype, head, len, policy, extack);
}
