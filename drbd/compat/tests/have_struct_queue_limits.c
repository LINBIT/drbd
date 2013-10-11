#include <linux/blkdev.h>

struct queue_limits *foo(void)
{
	struct queue_limits lim;

	return &lim;
}
