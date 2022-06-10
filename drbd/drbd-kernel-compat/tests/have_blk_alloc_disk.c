/* { "version": "v5.13-rc4", "commit": "b647ad024841d02d67e78716f51f355d8d3e9656", "comment": "5.13 introduces a blk_alloc_disk helper", "author": "Christoph Hellwig <hch@lst.de>", "date": "Fri May 21 07:50:57 2021 +0200" } */

#include <linux/blkdev.h>

struct gendisk *foo(int node)
{
	return blk_alloc_disk(node);
}
