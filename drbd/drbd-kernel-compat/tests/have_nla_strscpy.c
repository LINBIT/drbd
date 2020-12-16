/* { "version": "v5.10-rc4", "commit": "872f690341948b502c93318f806d821c56772c42", "comment": "nla_strlcpy was renamed to nla_strscpy", "author": "Francis Laniel <laniel_francis@privacyrequired.com>", "date": "Sun Nov 15 18:08:06 2020 +0100" } */

#include <net/netlink.h>

ssize_t foo(char *dst, const struct nlattr *nla, size_t dstsize)
{
	return nla_strscpy(dst, nla, dstsize);
}
