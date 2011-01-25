#include <linux/blkdev.h>
#include <linux/fs.h>

/*
 * In kernel version v2.6.28-rc1, open_bdev_excl() was replaced by
 * open_bdev_exclusive(); see commit 30c40d2.
 */
void foo(void)
{
	struct block_device *blkdev;

	blkdev = open_bdev_exclusive("", (fmode_t) 0, (void *) 0);
}
