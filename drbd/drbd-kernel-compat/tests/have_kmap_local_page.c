#include <linux/highmem.h>

void dummy(struct page *page)
{
	void *addr = kmap_local_page(page);

	kunmap_local(addr);
}
