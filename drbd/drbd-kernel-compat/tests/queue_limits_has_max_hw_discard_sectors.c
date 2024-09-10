/* { "version": "v6.9-rc1", "commit": "4f563a64732dabb2677c7d1232a8f714a18b41b3", "comment": "lim.max_hw_discard_sectors was added", "author": "Christoph Hellwig <hch@lst.de>", "date": "Tue Feb 13 08:34:16 2024 +0100" } */

#include <linux/blkdev.h>

int foo(struct queue_limits *lim)
{
	return lim->max_hw_discard_sectors;
}
