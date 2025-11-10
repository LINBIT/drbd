/* { "version": "v5.8", "commit": "c62b37d96b6eb3ec5ae4cbe00db107bf15aebc93", "comment": "Since 5.8 make_request_fn has been replaced by a block_device_operations method called submit_bio", "author": "Christoph Hellwig <hch@lst.de>", "date": "Wed Jul 1 10:59:43 2020 +0200" } */

#include <linux/blkdev.h>

#ifndef __same_type
# define __same_type(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))
#endif

blk_qc_t submit(struct bio *bio);

void foo(struct block_device_operations *ops)
{
	BUILD_BUG_ON(!(__same_type(ops->submit_bio, &submit)));
}
