#include <linux/blkdev.h>

void dummy(struct request_queue *q, struct bio *bio)
{
	blk_queue_split(q, &bio, q->bio_split);
}
