#include <linux/blkdev.h>

/*
 * In kernel version 2.6.38-rc1, open_bdev_exclusive() was replaced by
 * blkdev_get_by_path(); see commits e525fd89 and d4d77629.
 */
void foo(void) {
	struct block_device *blkdev;

	blkdev = blkdev_get_by_path("", (fmode_t) 0, (void *) 0);
}
