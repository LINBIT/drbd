/* { "version": "v5.16-rc2", "commit": "cd913c76f489def1a388e3a5b10df94948ede3f5", "comment": "fs_dax_get_by_bdev was changed to return the partition offset via a second parameter", "author": "Christoph Hellwig <hch@lst.de>", "date": "Mon Nov 29 11:21:59 2021 +0100" } */

#include <linux/blkdev.h>
#include <linux/dax.h>

struct dax_device *foo(struct block_device *bdev, u64 *start_off)
{
	return fs_dax_get_by_bdev(bdev, start_off);
}
