/* { "version": "v5.15-rc1", "commit": "21cf866145047f8bfecb38ec8d2fed64464c074f", "comment": "The backing_dev_info was moved from request_queue to backing_dev_info", "author": "Christoph Hellwig <hch@lst.de>", "date": "Wed Jul 1 11:06:22 2020 +0200" } */

#include <linux/blkdev.h>

struct backing_dev_info *foo(struct gendisk *d)
{
	return d->bdi;
}
