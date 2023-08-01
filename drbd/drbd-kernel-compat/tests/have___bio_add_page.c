/* { "version": "v4.18-rc1", "commit": "0aa69fd32a5f766e997ca8ab4723c5a1146efa8b", "comment": "__bio_add_page was introduced", "author": "Christoph Hellwig <hch@lst.de>", "date": "Fri Jun 1 09:03:05 2018 -0700" } */

#include <linux/bio.h>

void foo(struct bio *bio, struct page *page,
		unsigned int len, unsigned int off)
{
	__bio_add_page(bio, page, len, off);
}
