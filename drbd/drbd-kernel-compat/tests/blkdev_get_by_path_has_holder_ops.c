/* { "version": "v6.5-rc1", "commit": "0718afd47f70cf46877c39c25d06b786e1a3f36c", "comment": "block: introduce holder ops", "author": "Christoph Hellwig <hch@lst.de>", "date": "Thu Jun 1 11:44:52 2023 +0200" } */
#include <linux/blkdev.h>

struct block_device *foo(const char *bdev_path, struct blk_holder_ops *ops)
{
	return blkdev_get_by_path(bdev_path, 0, NULL, ops);
}
