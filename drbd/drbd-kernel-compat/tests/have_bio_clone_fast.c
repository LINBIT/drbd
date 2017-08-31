#include <linux/bio.h>

struct bio *dummy(void)
{
	struct bio *bio = NULL, *bio2;
	struct bio_set *bio_set = NULL;

	bio2 = bio_clone_fast(bio, GFP_NOIO, bio_set);

	return bio2;
}
