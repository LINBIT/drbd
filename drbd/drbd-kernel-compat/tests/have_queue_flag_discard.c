/* { "version": "v5.19-rc1", "commit": "70200574cc229f6ba038259e8142af2aa09e6976", "comment": "QUEUE_FLAG_DISCARD was removed", "author": "Christoph Hellwig <hch@lst.de>", "date": "Fri Apr 15 06:52:55 2022 +0200" } */

#include <linux/blkdev.h>

int foo = QUEUE_FLAG_DISCARD;
