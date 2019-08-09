//#include <linux/kernel.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/scatterlist.h>

// Taken from blk-lib.c

struct bio_batch {
	atomic_t		done;
	unsigned long		flags;
	struct completion	*wait;
};

static void bio_batch_end_io(struct bio *bio, int error)
{
	struct bio_batch *bb = bio->bi_private;

	if (error && (error != -EOPNOTSUPP))
		clear_bit(BIO_UPTODATE, &bb->flags);
	if (atomic_dec_and_test(&bb->done))
		complete(bb->wait);
	bio_put(bio);
}

/**
 * blkdev_issue_zeroout - zero-fill a block range
 * @bdev:	blockdev to write
 * @sector:	start sector
 * @nr_sects:	number of sectors to write
 * @gfp_mask:	memory allocation flags (for bio_alloc)
 * @flags:      controls detailed behavior (ignored)
 *
 * Description:
 *  Generate and issue number of bios with zerofiled pages.
 */

int blkdev_issue_zeroout(struct block_device *bdev, sector_t sector,
			 sector_t nr_sects, gfp_t gfp_mask)
{
	int ret;
	struct bio *bio;
	struct bio_batch bb;
	unsigned int sz;
	DECLARE_COMPLETION_ONSTACK(wait);

	atomic_set(&bb.done, 1);
	bb.flags = 1 << BIO_UPTODATE;
	bb.wait = &wait;

	ret = 0;
	while (nr_sects != 0) {
		bio = bio_alloc(gfp_mask,
				min(nr_sects, (sector_t)BIO_MAX_PAGES));
		if (!bio) {
			ret = -ENOMEM;
			break;
		}

		bio->bi_sector = sector;
		bio->bi_bdev   = bdev;
		bio->bi_end_io = bio_batch_end_io;
		bio->bi_private = &bb;

		while (nr_sects != 0) {
			sz = min((sector_t) PAGE_SIZE >> 9 , nr_sects);
			ret = bio_add_page(bio, ZERO_PAGE(0), sz << 9, 0);
			nr_sects -= ret >> 9;
			sector += ret >> 9;
			if (ret < (sz << 9))
				break;
		}
		ret = 0;
		atomic_inc(&bb.done);
#if 0
/* This file is only compiled for old kernels not exporting blkdev_issue_zeroout().
 * Avoid to include "drbd_wrappers.h", use the old sumit_bio() directly
 * without macro-indirection magic */
		bio_set_op_attrs(bio, REQ_OP_WRITE, 0);
		submit_bio(bio);
#else
		submit_bio(WRITE, bio);
#endif
	}

	/* Wait for bios in-flight */
	if (!atomic_dec_and_test(&bb.done))
		wait_for_completion(&wait);

	if (!test_bit(BIO_UPTODATE, &bb.flags))
		/* One of bios in the batch was completed with error.*/
		ret = -EIO;

	return ret;
}

