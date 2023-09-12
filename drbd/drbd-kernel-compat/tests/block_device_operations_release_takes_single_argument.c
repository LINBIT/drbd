/* { "version": "v6.5-rc1", "commit": "ae220766d87cd6799dbf918fea10613ae14c0654", "comment": "block: remove the unused mode argument to ->release", "author": "Christoph Hellwig <hch@lst.de>", "date": "Thu Jun 8 13:02:37 2023 +0200" } */
#include <linux/blkdev.h>

void foo(struct block_device_operations *ops, struct gendisk *gd)
{
	ops->release(gd);
}
