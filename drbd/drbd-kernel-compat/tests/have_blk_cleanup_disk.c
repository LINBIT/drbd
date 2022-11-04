/* { "version": "v6.1-rc3", "commit": "8b9ab62662048a3274361c7e5f64037c2c133e2c", "comment": "blk_cleanup_disk was removed", "author": "Christoph Hellwig <hch@lst.de>", "date": "Sun Jun 19 08:05:52 2022 +0200" } */

#include <linux/blkdev.h>

void foo(struct gendisk *disk)
{
	blk_cleanup_disk(disk);
}
