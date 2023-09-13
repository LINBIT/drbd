/* { "version": "v6.5-rc1", "commit": "05bdb9965305bbfdae79b31d22df03d1e2cfcb22", "comment": "block: replace fmode_t with a block-specific type for block open flags", "author": "Christoph Hellwig <hch@lst.de>", "date": "Thu Jun 8 13:02:55 2023 +0200" } */
#include <linux/blkdev.h>

void foo(blk_mode_t mode) {}
