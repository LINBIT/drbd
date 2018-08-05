#include <linux/bio.h>
/*
With linux v4.18 biosets get embedded
commit 917a38c71af82185c39e31589587591fa764fb85
Author: Kent Overstreet <kent.overstreet@gmail.com>
Date:   Tue May 8 21:33:51 2018 -0400
*/

static struct bio_set foo(void)
{
	struct bio_set bio_set;
	int err;

	err = bioset_init(&bio_set, 10, 0, 0);

	return bio_set;
}
