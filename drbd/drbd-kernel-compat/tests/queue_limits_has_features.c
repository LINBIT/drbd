/* { "version": "v6.10", "commit": "1122c0c1cc71f740fa4d5f14f239194e06a1d5e7", "comment": "features field was introduced", "author": "Christoph Hellwig <hch@lst.de>", "date": "Mon Jun 17 08:04:40 2024 +0200" } */

#include <linux/blkdev.h>

unsigned int foo(struct queue_limits lim)
{
       return lim.features;
}
