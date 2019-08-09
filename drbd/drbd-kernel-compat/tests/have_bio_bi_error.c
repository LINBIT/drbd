#include <linux/bio.h>

void dummy(struct bio *bio)
{
	bio->bi_error = -EIO;
	bio_endio(bio);
}
