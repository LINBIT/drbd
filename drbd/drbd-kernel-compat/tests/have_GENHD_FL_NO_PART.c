/* { "version": "v5.16-rc4", "commit": "46e7eac647b34ed4106a8262f8bedbb90801fadd", "comment": "GENHD_FL_NO_PART_SCAN was renamed to GENHD_FL_NO_PART", "author": "Christoph Hellwig <hch@lst.de>", "date": "Mon Nov 22 14:06:17 2021 +0100" } */

#include <linux/blkdev.h>

int foo(void)
{
	return GENHD_FL_NO_PART;
}
