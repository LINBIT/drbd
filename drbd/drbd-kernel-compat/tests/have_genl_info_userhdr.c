/* { "version": "v6.6-rc1", "commit": "bffcc6882a1bb2be8c9420184966f4c2c822078e", "comment": "genetlink: remove userhdr from struct genl_info", "author": "Jakub Kicinski <kuba@kernel.org>", "date": "Mon Aug 14 14:47:16 2023 -0700" } */
#include <net/genetlink.h>

void *foo(struct genl_info *info)
{
	return genl_info_userhdr(info);
}
