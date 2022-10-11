/* { "version": "v5.19-rc1", "commit": "cf0fbf894bb543f472f682c486be48298eccf199", "comment": "The bdev_max_discard_sectors was added", "author": "Christoph Hellwig <hch@lst.de>", "date": "Fri Apr 15 06:52:54 2022 +0200" } */

#include <linux/blkdev.h>

unsigned int foo(struct block_device *bdev)
{
	return bdev_max_discard_sectors(bdev);
}
