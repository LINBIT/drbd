/* { "version": "v5.8-rc1", "commit": "88dca4ca5a93d2c09e5bbc6a62fbfc3af83c4fca", "comment": "pgprot argument to __vmalloc was removed", "author": "Christoph Hellwig <hch@lst.de>", "date": "Mon Jun 1 21:51:40 2020 -0700" } */

#include <linux/vmalloc.h>

void foo(void)
{
	__vmalloc(0, 0);
}
