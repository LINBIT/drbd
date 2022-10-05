/* {"version":"4.17"} */
#include <linux/blkdev.h>

void dummy(struct request_queue *q)
{
	blk_queue_flag_set(0, q);
}
