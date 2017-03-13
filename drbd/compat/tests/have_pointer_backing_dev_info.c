#include <linux/blkdev.h>

void test(void)
{
	struct request_queue q = {};
	q.backing_dev_info = NULL;
}
