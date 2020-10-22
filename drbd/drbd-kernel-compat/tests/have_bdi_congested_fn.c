/* { "version": "v5.8-rc2", "commit": "21cf866145047f8bfecb38ec8d2fed64464c074f", "comment": "In 5.8 bdi->congested_fn was removed", "author": "Christoph Hellwig <hch@lst.de>", "date": "Wed Jul 1 11:06:22 2020 +0200" } */

#include <linux/blkdev.h>

void foo(struct backing_dev_info bdi)
{
	bdi.congested_fn = NULL;
}
