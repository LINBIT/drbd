/* { "version": "v5.10-rc5", "commit": "8446fe9255be821cb38ffd306d7e8edc4b9ea662", "comment": "partition lookup was changed to expect a struct block_device", "author": "Christoph Hellwig <hch@lst.de>", "date": "Tue Nov 24 09:36:54 2020 +0100" } */

#include <linux/blk_types.h>
#include <linux/part_stat.h>

int foo(struct block_device *d)
{
	return (int)part_stat_read(d, sectors[0]);
}
