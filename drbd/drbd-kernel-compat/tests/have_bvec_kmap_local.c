/* { "version": "v5.15-rc1", "commit": "e6e7471706dc42cbe0e01278540c0730138d43e5", "comment": "The bvec_kmap_local helper was added", "author": "Christoph Hellwig <hch@lst.de>", "date": "Tue Jul 27 07:56:34 2021 +0200" } */

#include <linux/bvec.h>

void *foo(struct bio_vec *bvec)
{
	return bvec_kmap_local(bvec);
}
