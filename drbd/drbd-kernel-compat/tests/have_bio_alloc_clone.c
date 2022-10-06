/* { "version": "v5.18-rc1", "commit": "abfc426d1b2fb2176df59851a64223b58ddae7e7", "comment": "bio_clone_fast was renamed to bio_alloc_clone and had its signature changed", "author": "Christoph Hellwig <hch@lst.de>", "date": "Wed Feb 2 17:01:09 2022 +0100" } */

#include <linux/bio.h>

struct bio *dummy(struct block_device *bdev, struct bio *bio_src, gfp_t gfp,
		struct bio_set *bs)
{
	return bio_alloc_clone(bdev, bio_src, gfp, bs);
}
