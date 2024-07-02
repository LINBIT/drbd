/* { "version": "v6.9-rc1", "commit": "74fa8f9c553f7b5ccab7d103acae63cc2e080465", "comment": "block: pass a queue_limits argument to blk_alloc_disk", "author": "Christoph Hellwig <hch@lst.de>", "date": "Thu Feb 15 08:10:47 2024 +0100" } */

#include <linux/blkdev.h>

struct gendisk *foo(struct queue_limits *lim, int node)
{
	return blk_alloc_disk(lim, node);
}
