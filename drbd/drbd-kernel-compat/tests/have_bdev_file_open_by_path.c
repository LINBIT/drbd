/* { "version": "v6.9-rc1", "commit": "f3a608827d1f8de0dd12813e8d9c6803fe64e119", "comment": "bdev: open block devices as files", "author": "Christian Brauner <brauner@kernel.org>", "date": "Thu Feb 8 18:47:35 2024 +0100" } */

#include <linux/blkdev.h>

struct file *foo(const char *path, blk_mode_t mode, void *holder,
		const struct blk_holder_ops *hops)
{
	return bdev_file_open_by_path(path, mode, holder, hops);
}
