/* { "version": "v5.9-rc4", "commit": "c2e4cd57cfa1f627b786c764d185fff85fd12be9", "comment": "In v5.9-rc4 blk_queue_update_readahead was introduced", "author": "Christoph Hellwig <hch@lst.de>", "date": "Thu Sep 24 08:51:34 2020 +0200" } */

#include <linux/blkdev.h>

void foo(struct request_queue *q)
{
	blk_queue_update_readahead(q);
}
