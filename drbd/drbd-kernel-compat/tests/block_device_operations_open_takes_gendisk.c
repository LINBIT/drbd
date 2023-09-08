/* { "version": "v6.5-rc1", "commit": "d32e2bf83791727a84ad5d3e3d713e82f9adbe30", "comment": "block: pass a gendisk to ->open", "author": "Christoph Hellwig <hch@lst.de>", "date": "Thu Jun 8 13:02:36 2023 +0200" } */
#include <linux/blkdev.h>

#ifndef __same_type
# define __same_type(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))
#endif

int foo_open(struct gendisk *disk, unsigned int mode)
{
	return 0;
}

void foo(void)
{
	struct block_device_operations ops;
	BUILD_BUG_ON(!(__same_type(ops.open, &foo_open)));
}
