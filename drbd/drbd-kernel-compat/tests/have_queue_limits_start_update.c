/* { "version": "v6.9-rc1", "commit": "d690cb8ae14bd377d422b7905b6959c7e7a45b95", "comment": "block: add an API to atomically update queue limits", "author": "Christoph Hellwig <hch@lst.de>", "date": "Tue Feb 13 08:34:14 2024 +0100" } */

#include <linux/blkdev.h>

static struct queue_limits foo(struct request_queue *q)
{
	return queue_limits_start_update(q);
}
