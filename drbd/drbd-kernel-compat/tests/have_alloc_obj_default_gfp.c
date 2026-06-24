/* { "version": "v7.0-rc1", "commit": "e19e1b480ac73c3e62ffebbca1174f0f511f43e7", "comment": "alloc_obj family defaults to GFP_KERNEL when no gfp argument given", "author": "Linus Torvalds <torvalds@linux-foundation.org>", "date": "Sat Feb 21 16:14:11 2026 -0800" } */
#include <linux/slab.h>

void *foo(void)
{
	return kmalloc_obj(struct page);
}
