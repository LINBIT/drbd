#include <linux/bio.h>

int main(void)
{
	struct bio *bio = NULL;
	struct bio_set *bio_set = NULL;

	bio_free(bio, bio_set);
	return 0;
}
