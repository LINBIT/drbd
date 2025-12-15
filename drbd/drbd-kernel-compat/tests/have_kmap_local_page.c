/* { "version": "v5.11-rc1", "commit": "f3ba3c710ac5a30cd058615a9eb62d2ad95bb782", "comment": "kmap_local* introduced", "author": "Thomas Gleixner <tglx@linutronix.de>", "date": "Wed Nov 18 20:48:44 2020 +0100" } */

void dummy(struct page *page)
{
	void *addr = kmap_local_page(page);

	kunmap_local(addr);
}
