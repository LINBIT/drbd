/* { "version": "v5.8-rc2", "commit": "ed00aabd5eb9fb44d6aff1173234a2e911b9fead", "comment": "Since 5.8 generic_make_request has been renamed to submit_bio_noacct", "author": "Christoph Hellwig <hch@lst.de>", "date": "Wed Jul 1 10:59:44 2020 +0200" } */

#include <linux/blkdev.h>

void foo(struct bio *bio)
{
	blk_qc_t result;

	result = submit_bio_noacct(bio);
}
