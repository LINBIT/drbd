/* { "version": "v5.11", "commit": "5f7136db82996089cdfb2939c7664b29e9da141d", "comment": "block: Add bio_max_segs", "author": "Matthew Wilcox (Oracle) <willy@infradead.org>", "date": "Fri Jan 29 04:38:57 2021 +0000" } */

#include <linux/bio.h>

unsigned int foo(unsigned int nr_segs)
{
	return bio_max_segs(nr_segs);
}
