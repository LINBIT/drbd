#include <linux/bio.h>

/*
 * bio_split() had a memory pool parameter until commit 6feef53 (2.6.28-rc1).
 */
void test(void)
{
	struct bio *bio = NULL;
	struct bio_pair *bio_pair;

	bio_pair = bio_split(bio, bio_split_pool, 0);
}
