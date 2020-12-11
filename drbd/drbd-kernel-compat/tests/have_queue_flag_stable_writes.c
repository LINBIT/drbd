/* { "version": "v5.9-rc4", "commit": "1cb039f3dc1619eb795c54aad0a98fdb379b4237", "comment": "BDI_CAP_STALBE_WRITES as a backing_dev_info flag is gone, it is now the queue flag QUEUE_FLAG_STABLE_WRITES", "author": "Christoph Hellwig <hch@lst.de>", "date": "Thu Sep 24 08:51:38 2020 +0200" } */

#include <linux/blkdev.h>

int foo(void)
{
	return QUEUE_FLAG_STABLE_WRITES;
}
