#include <linux/blkdev.h>

void dummy(struct request_queue *q)
{
	blk_queue_merge_bvec(q, NULL);
}
