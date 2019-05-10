/* {"version":"4.18", "commit":"917a38c71af82185c39e31589587591fa764fb85", "comment":"With linux v4.18 biosets get embedded", "author":"Kent Overstreet <kent.overstreet@gmail.com>", "date":"Tue May 8 21:33:51 2018 -0400"} */
#include <linux/bio.h>

static struct bio_set foo(void)
{
	struct bio_set bio_set;
	int err;

	err = bioset_init(&bio_set, 10, 0, 0);

	return bio_set;
}
