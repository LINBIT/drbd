#include <linux/blkdev.h>

void dummy(struct request_queue *q, bool enabled, bool fua)
{
	blk_queue_write_cache(q, enabled, fua);
}
