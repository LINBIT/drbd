/* { "version": "v5.9-rc4", "commit": "659e56ba864d37b7ee0a49cd432205b2a5ca815e", "comment": "The revalidate_disk_size helper was added in v5.9-rc4", "author": "Christoph Hellwig <hch@lst.de>", "date": "Tue Sep 1 17:57:43 2020 +0200" } */

#include <linux/genhd.h>

void foo(struct gendisk *disk)
{
	revalidate_disk_size(disk, false);
}
