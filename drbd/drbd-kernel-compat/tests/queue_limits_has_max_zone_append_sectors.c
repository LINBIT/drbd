/* { "version": "v5.7-rc3", "commit": "0512a75b98f847c2e9a4b664013424e603e202f7", "comment": "max_zone_append_sectors introduced", "author": "Keith Busch <kbusch@kernel.org>", "date": "Tue May 12 17:55:47 2020 +0900" } */

#include <linux/blkdev.h>

int foo(struct queue_limits *lim)
{
	return lim->max_zone_append_sectors;
}
