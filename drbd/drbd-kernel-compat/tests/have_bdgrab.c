/* { "version": "v5.14-rc5", "commit": "14cf1dbb55bb07427babee425fd2a8a9300737cc", "comment": "bdgrab was removed", "author": "Christoph Hellwig <hch@lst.de>", "date": "Thu Jul 22 09:54:01 2021 +0200" } */

#include <linux/blkdev.h>

struct block_device *foo(struct block_device *b) {
	return bdgrab(b);
}
