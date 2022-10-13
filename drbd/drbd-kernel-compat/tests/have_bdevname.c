/* { "version": "v5.19-rc5", "commit": "900d156bac2bc474cf7c7bee4efbc6c83ec5ae58", "comment": "the bdevname helper was removed", "author": "Christoph Hellwig <hch@lst.de>", "date": "Wed Jul 13 07:53:17 2022 +0200" } */

#include <linux/blkdev.h>

const char *foo(struct block_device *bdev, char *buf)
{
	return bdevname(bdev, b);
}
