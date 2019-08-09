/* { "version": "v4.8", "commit": "1eff9d322a444245c67515edb52bc0eb68374aa8", "comment": "bio->bi_rw was renamed to bio->bi_opf", "author": "Jens Axboe <axboe@fb.com>", "date": "Fri Aug 5 15:35:16 2016 -0600" } */
#include <linux/bio.h>

void dummy(struct bio *bio)
{
	bio->bi_opf = 0;
}
