/* { "version": "v5.18-rc4", "commit": "7b47ef52d0a2025fd1408a8a0990933b8e1e510f", "comment": "A new helper, bdev_discard_granularity, was added", "author": "Christoph Hellwig <hch@lst.de>", "date": "Fri Apr 15 06:52:56 2022 +0200" } */

#include <linux/blkdev.h>

unsigned int foo(struct block_device *bdev)
{
	return bdev_discard_granularity(bdev);
}
