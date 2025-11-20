/* { "version": "v5.11-rc1", "commit": "040f04bd2e825f1d80b14a0e0ac3d830339eb779", "comment": "fs: simplify freeze_bdev/thaw_bdev", "author": "Christoph Hellwig <hch@lst.de>", "date": "Tue Nov 24 11:54:06 2020 +0100" } */

#include <linux/blkdev.h>

struct super_block *foo(struct block_device *bdev)
{
	return freeze_bdev(bdev);
}
