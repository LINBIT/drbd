#include <linux/bio.h>

void dummy(void)
{
	struct bio bio;
	bio.bi_destructor = NULL;
}
