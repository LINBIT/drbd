/* { "version": "v6.3-rc3", "commit": "5f27571382ca42daa3e3d40d1b252bf18c2b61d2", "comment": "bio-based devices count sectors in bdev_end_io_acct(), at completion, not at submission", "author": "Yu Kuai <yukuai3@huawei.com>", "date": "Thu Feb 23 17:12:26 2023 +0800" } */

#include <linux/blkdev.h>

void foo(struct block_device *bdev, unsigned long start_time)
{
	bdev_end_io_acct(bdev, REQ_OP_READ, 8, start_time);
}
