/* { "version": "v5.10-rc5", "commit": "a782483cc1f875355690625d8253a232f2581418", "comment": "the bdev_nr_sectors helper was introduced", "author": "Christoph Hellwig <hch@lst.de>", "date": "Thu Nov 26 18:43:37 2020 +0100" } */

#include <linux/blkdev.h>

sector_t foo(struct block_device *bdev)
{
	return bdev_nr_sectors(bdev);
}
