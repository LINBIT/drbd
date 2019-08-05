/* {"version":"2.6.39", "commit": "7eaceaccab5f40bbfda044629a6298616aeaed50", "comment": "With Linux 2.6.39, per-queue plugging goes away", "author": "Jens Axboe <jaxboe@fusionio.com>", "date": "Thu Mar 10 08:52:07 2011 +0100" } */
#include <linux/blkdev.h>

void dummy(struct request_queue *q)
{
	blk_queue_plugged(q);
}
