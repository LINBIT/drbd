#include <linux/bio.h>

/*
 * bio_set_op_attrs() change to inline since 93c5bdf7 (4.10-rc1)
 */
void test(void)
{
	struct bio *bio = NULL;

	bio_set_op_attrs(bio, 0, 0);
}
