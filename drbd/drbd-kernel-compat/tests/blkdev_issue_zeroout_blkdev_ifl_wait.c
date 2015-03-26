#include <linux/blkdev.h>

/* In 2.6.34 and 2.6.35 this function had 5 parameters. Later the
   flags parameter was dropped;
   and in linux 4, we get a 5th parameter back, as "bool discard".
   Fortunately, BLKDEV_IFL_WAIT was dropped when "flags" was dropped,
   so this basically checks if BLKDEV_IFL_WAIT is known. */

#ifndef __same_type
# define __same_type(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))
#endif

extern int biz_fn(struct block_device *bdev, sector_t start, sector_t len, gfp_t gfp_mask, unsigned long flags);

int foo(void)
{
	struct block_device *bdev = NULL;
	sector_t start = 0;
	sector_t len = 0;
	BUILD_BUG_ON(!(__same_type(biz_fn, blkdev_issue_zeroout)));
	return blkdev_issue_zeroout(bdev, start, len, GFP_KERNEL, BLKDEV_IFL_WAIT);
}
