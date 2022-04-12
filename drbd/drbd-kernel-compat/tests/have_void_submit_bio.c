/* { "version": "v5.15-rc7", "commit": "3e08773c3841e9db7a520908cc2b136a77d275ff", "comment": "submit_bio changed from a blk_qc_t return value to void", "author": "Christoph Hellwig <hch@lst.de>", "date": "Tue Oct 12 13:12:24 2021 +0200" } */

#include <linux/blkdev.h>

void submit(struct bio *bio);

void foo(struct block_device_operations *ops)
{
	ops->submit_bio = submit;
}
