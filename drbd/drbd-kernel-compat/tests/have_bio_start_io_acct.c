/* { "version": "v5.7-rc3", "commit": "24d69293d9a561645e0b4d78c2fb179827e35f53", "comment": "some new helpers, bio_{start,end}_io_acct were introduced. they are supposed to replace generic_{start,end}_io_acct for bio-based drivers", "author": "Christoph Hellwig <hch@lst.de>", "date": "Wed May 27 07:24:05 2020 +0200" } */

#include <linux/blkdev.h>

void foo(void)
{
	unsigned long jif;
	jif = bio_start_io_acct(NULL);
}
