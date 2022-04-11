/* { "version": "v5.14-rc5", "commit": "83cbce9574462c6b4eed6797bdaf18fae6859ab3", "comment": "add_disk gained error handling, changing its return type to int", "author": "Luis Chamberlain <mcgrof@kernel.org>", "date": "Wed Aug 18 16:45:40 2021 +0200" } */

#include <linux/blkdev.h>

int foo(struct gendisk *d)
{
	return add_disk(d);
}
