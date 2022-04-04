/* { "version": "v5.17-rc1", "commit": "471aa704db4904f7af5a50019ca3b5b018c0cf62", "comment": "In v5.17-rc1 blk_queue_update_readahead was renamed to disk_update_readahead", "author": "Christoph Hellwig <hch@lst.de>", "date": "Mon Aug 9 16:17:41 2021 +0200" } */

#include <linux/blkdev.h>

void foo(struct gendisk *d)
{
	disk_update_readahead(d);
}
