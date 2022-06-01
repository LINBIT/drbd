/* { "version": "v5.10-rc5", "commit": "0d02129e76edf91cf04fabf1efbc3a9a1f1d729a", "comment": "struct hd_struct was merged into struct block_device", "author": "Christoph Hellwig <hch@lst.de>", "date": "Fri Nov 27 16:43:51 2020 +0100" } */

#include <linux/blkdev.h>

struct hd_struct hd;
