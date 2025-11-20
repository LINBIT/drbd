/* { "version": "v6.8-rc1", "commit": "982c3b3058433f20aba9fb032599cee5dfc17328", "comment": "bdev: rename freeze and thaw helpers", "author": "Christian Brauner <brauner@kernel.org>", "date": "Tue Oct 24 15:01:08 2023 +0200" } */

#include <linux/blkdev.h>

int foo(struct block_device *bdev)
{
	return bdev_freeze(bdev);
}
