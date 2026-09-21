/* { "version": "v6.2-rc1", "commit": "51c352bdbcd23d7ce46b06c1e64c82754dc44044", "comment": "netlink: add support for formatted extack messages - NL_SET_ERR_MSG_FMT() and NETLINK_MAX_FMTMSG_LEN; distributions backported the split genetlink ops without these, so test for them separately", "author": "Edward Cree <ecree.xilinx@gmail.com>", "date": "Tue Oct 18 15:37:27 2022 +0200" } */
#include <linux/netlink.h>

void foo(struct netlink_ext_ack *extack, const char *msg)
{
	NL_SET_ERR_MSG_FMT(extack, "%.*s", NETLINK_MAX_FMTMSG_LEN - 1, msg);
}
