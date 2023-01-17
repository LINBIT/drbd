/* { "version": "v6.0-rc1", "commit": "8012b866085523758780850087102421dbcce522", "comment": "fs_dax_get_by_bdev was changed to take optional holder parameters", "author": "Shiyang Ruan <ruansy.fnst@fujitsu.com>", "date": "Fri Jun 3 13:37:25 2022 +0800" } */

#include <linux/blkdev.h>
#include <linux/dax.h>

struct dax_device *foo(struct block_device *bdev, u64 *start_off, void *holder, const struct dax_holder_operations *ops)
{
	return fs_dax_get_by_bdev(bdev, start_off, holder, ops);
}
