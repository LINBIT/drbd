#include <linux/blkdev.h>

void foo(void)
{
	struct queue_limits *lim = NULL;

	blk_set_stacking_limits(lim);
}
