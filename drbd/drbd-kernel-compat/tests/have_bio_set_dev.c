/* { "version": "v4.13-rc3", "commit": "74d46992e0d9dee7f1f376de0d56d31614c8a17a", "comment": "bio_set_dev was introduced", "author": "Christoph Hellwig <hch@lst.de>", "date": "Wed Aug 23 19:10:32 2017 +0200" } */

#include <linux/bio.h>

void foo(struct bio *bio, struct block_device *bdev)
{
	bio_set_dev(bio, bdev);
}
