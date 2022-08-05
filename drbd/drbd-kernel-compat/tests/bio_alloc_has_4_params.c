/* { "version": "v5.17-rc3", "commit": "07888c665b405b1cd3577ddebfeb74f4717a84c4", "comment": "bio_alloc got two new arguments", "author": "Christoph Hellwig <hch@lst.de>", "date": "Mon Jan 24 10:11:05 2022 +0100" } */

/* note: this result is also valid for bio_alloc_bioset, since the same
   signature change was made there in the same patch series. */

#include <linux/bio.h>

struct bio *foo(struct block_device *bdev, unsigned short nr_vecs,
		unsigned int opf, gfp_t gfp_mask)
{
	return bio_alloc(bdev, nr_vecs, opf, gfp_mask);
}
