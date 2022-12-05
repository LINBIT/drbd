/* { "version": "v6.0-rc1", "commit": "5a97806f7dc069d9561d9930a2ae108700e222ab", "comment": "blk_queue_split was renamed to bio_split_to_limits", "author": "Christoph Hellwig <hch@lst.de>", "date": "Wed Jul 27 12:22:55 2022 -0400" } */

#include <linux/blkdev.h>

struct bio *foo(struct bio *b)
{
	return bio_split_to_limits(b);
}
