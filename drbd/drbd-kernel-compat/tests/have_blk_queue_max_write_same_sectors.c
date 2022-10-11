/* { "version": "v5.18-rc1", "commit": "73bd66d9c834220579c881a3eb020fd8917075d8", "comment": "REQ_OP_WRITE_SAME was removed, and with it this helper", "author": "Christoph Hellwig <hch@lst.de>", "date": "Wed Feb 9 09:28:28 2022 +0100" } */

#include <linux/blkdev.h>

void foo(struct request_queue *q, unsigned int s)
{
	blk_queue_max_write_same_sectors(q, s);
}
