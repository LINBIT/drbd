/* { "version": "v5.12-rc2", "commit": "a8affc03a9b375e19bc81573de0c9108317d78c7", "comment": "rename BIO_MAX_PAGES to BIO_MAX_VECS", "author": "Christoph Hellwig <hch@lst.de>", "date": "Thu Mar 11 12:01:37 2021 +0100" } */

#include <linux/bio.h>

int foo(void)
{
	return BIO_MAX_VECS;
}
