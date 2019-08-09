#include <linux/blkdev.h>

#ifndef __same_type
# define __same_type(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))
#endif

extern int biz_fn(struct block_device *bdev, sector_t start, sector_t len, gfp_t gfp_mask, bool discard);

int foo(void)
{
	struct block_device *bdev = NULL;
	sector_t start = 0;
	sector_t len = 0;
	BUILD_BUG_ON(!(__same_type(biz_fn, blkdev_issue_zeroout)));
	return blkdev_issue_zeroout(bdev, start, len, GFP_KERNEL, false);
}
