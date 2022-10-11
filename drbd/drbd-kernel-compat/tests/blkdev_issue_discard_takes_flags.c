/* { "version": "v5.19-rc1", "commit": "44abff2c0b970ae3d310b97617525dc01f248d7c", "comment": "blkdev_issue_discard had its last parameter (flags) removed", "author": "Christoph Hellwig <hch@lst.de>", "date": "Fri Apr 15 06:52:57 2022 +0200" } */

#include <linux/blkdev.h>

int foo(struct block_device *bdev, sector_t sector, sector_t nr_sects,
	gfp_t gfp_mask, unsigned long flags)
{
	return blkdev_issue_discard(bdev, sector, nr_sects, gfp_mask, flags);
}
