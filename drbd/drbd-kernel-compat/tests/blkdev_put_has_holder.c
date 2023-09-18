/* { "version": "v6.5-rc1", "commit": "ae220766d87cd6799dbf918fea10613ae14c0654", "comment": "block: remove the unused mode argument to ->release", "author": "Christoph Hellwig <hch@lst.de>", "date": "Thu Jun 8 13:02:37 2023 +0200" } */
#include <linux/blkdev.h>

#ifndef __same_type
# define __same_type(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))
#endif

void foo_blkdev_put(struct block_device *bdev, void *holder)
{
}


void foo(void)
{
	BUILD_BUG_ON(!(__same_type(&blkdev_put, &foo_blkdev_put)));
}

