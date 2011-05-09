#include <linux/bio.h>

/*
 * Note that up until 2.6.21 inclusive, it was
 * struct bio_set *bioset_create(int bio_pool_size, int bvec_pool_size, int scale)
 */
void dummy(void)
{
	bioset_create(16, 16, 4);
}
