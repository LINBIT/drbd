#include <linux/bio.h>

void dummy(struct bio *bio)
{
	bio->bi_status = BLK_STS_IOERR;
	bio_endio(bio);
}
