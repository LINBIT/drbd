/* { "version": "v5.15-rc1", "commit": "1113f0b69c6a98ff4e733c306a6658a31f8cbc49", "comment": "The bvec_virt helper was added", "author": "Christoph Hellwig <hch@lst.de>", "date": "Wed Aug 4 11:56:20 2021 +0200" } */

#include <linux/bvec.h>

void *foo(struct bio_vec *bvec)
{
	return bvec_virt(bvec);
}
