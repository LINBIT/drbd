/* { "version": "v6.13-rc1", "commit": "559218d43ec9dde3d2847c7aa127e88d6ab1c9ed", "comment": "max_hw_zone_append_sectors introduced", "author": "Christoph Hellwig <hch@lst.de>", "date": "Fri Nov 8 16:46:51 2024 +0100" } */

#include <linux/blkdev.h>

int foo(struct queue_limits *lim)
{
	return lim->max_hw_zone_append_sectors;
}
