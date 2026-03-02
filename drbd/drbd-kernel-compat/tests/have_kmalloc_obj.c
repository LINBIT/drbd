/* {"version": "v7.0-rc1", "commit": "69050f8d6d075dc01af7a5f2f550a8067510366f", "comment": "kmalloc_obj was added as a type-safe kmalloc wrapper", "author": "Kees Cook <kees@kernel.org>", "date": "Fri Feb 20 23:49:23 2026 -0800"} */
#include <linux/slab.h>

void *foo(void)
{
	return kmalloc_obj(struct page, GFP_KERNEL);
}
