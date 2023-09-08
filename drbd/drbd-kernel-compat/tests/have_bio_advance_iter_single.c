#include <linux/bio.h>

void dummy(struct bio *bio)
{
	struct bvec_iter iter = bio->bi_iter;

	bio_advance_iter_single(bio, &iter, 17);
}
