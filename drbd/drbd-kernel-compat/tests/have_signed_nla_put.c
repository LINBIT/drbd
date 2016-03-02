#include <net/netlink.h>

void foo(void)
{
	nla_put_s32(NULL, 0, 0);
}
