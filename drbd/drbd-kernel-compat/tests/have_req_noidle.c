/* { "version": "v4.10", "commit": "a2b809672ee6fcb4d5756ea815725b3dbaea654e", "comment": "REQ_NOIDLE was renamed to REQ_IDLE, and the whole logic was turned around", "author": "Christoph Hellwig <hch@lst.de>", "date": "Tue Nov 1 07:40:09 2016 -0600" } */
#include <linux/blk_types.h>

int dummy = REQ_NOIDLE;
