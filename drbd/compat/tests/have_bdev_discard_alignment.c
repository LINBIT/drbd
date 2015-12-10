#include <linux/blkdev.h>

int dummy(struct block_device *bdev)
{
	return bdev_discard_alignment(bdev);
}
