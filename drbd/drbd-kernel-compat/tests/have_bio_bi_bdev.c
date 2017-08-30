#include <linux/bio.h>

void dummy(struct bio *bio)
{
	bio->bi_bdev = NULL;
}
