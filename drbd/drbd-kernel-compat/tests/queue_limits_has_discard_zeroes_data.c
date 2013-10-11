#include <linux/blkdev.h>

struct queue_limits *foo(void)
{
	struct queue_limits *lim = NULL;

	lim->discard_zeroes_data = 1;

	return lim;
}
