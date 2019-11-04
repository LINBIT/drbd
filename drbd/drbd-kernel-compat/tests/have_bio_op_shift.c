/* { "version": "v4.10", "commit": "ef295ecf090d3e86e5b742fc6ab34f1122a43773", "comment": "BIO_OP_SHIFT", "author": "Christoph Hellwig <hch@lst.de>", "date": "Fri Oct 28 08:48:16 2016 -0600" } */
#include <linux/blk_types.h>

int dummy = BIO_OP_SHIFT;
