/* { "version": "v5.9", "commit": "f695ca3886ce72b027af7aa6040cd420cae2088c", "comment": "In 5.9, blk_queue_split lost its first parameter, since the bio can be derived from the queue", "author": "Christoph Hellwig <hch@lst.de>", "date": "Wed Jul 1 10:59:39 2020 +0200" } */


#include <linux/blkdev.h>

void dummy(struct bio *bio)
{
	blk_queue_split(&bio);
}
