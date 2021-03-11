/* { "version": "v5.10-rc5", "commit": "449f4ec9892ebc2f37a7eae6d97db2cf7c65e09a", "comment": "New (as far as DRBD is concerned) helper set_capacity_and_notify", "author": "Christoph Hellwig <hch@lst.de>", "date": "Mon Nov 16 15:56:56 2020 +0100" } */

#include <linux/genhd.h>

bool foo(struct gendisk *disk, sector_t size)
{
	return set_capacity_and_notify(disk, size);
}
