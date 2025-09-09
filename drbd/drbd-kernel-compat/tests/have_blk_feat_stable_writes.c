/* { "version": "v6.10-rc4", "commit": "1a02f3a73f8c670eddeb44bf52a75ae7f67cfc11", "comment": "block: move the stable_writes flag to queue_limits", "author": "Christoph Hellwig <hch@lst.de>", "date": "Mon Jun 17 08:04:44 2024 +0200" } */

#include <linux/blkdev.h>

int foo(void)
{
	return BLK_FEAT_STABLE_WRITES;
}
