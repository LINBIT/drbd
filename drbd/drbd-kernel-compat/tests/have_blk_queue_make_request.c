/* { "version": "v5.6-rc7", "commit": "3d745ea5b095a3985129e162900b7e6c22518a9d", "comment": "blk_queue_make_request was removed, users should now pass the make_request function to blk_alloc_queue", "author": "Christoph Hellwig <hch@lst.de>", "date": "Fri Mar 27 09:30:11 2020 +0100" } */

#include <linux/blkdev.h>

void foo(void)
{
	blk_queue_make_request(NULL, NULL);
}
