/* { "version": "v2.6.36", "commit": "33659ebbae262228eef4e0fe990f393d1f0ed941", "comment": "before REQ_WRITE there was BIO_RW", "author": "Christoph Hellwig <hch@lst.de>", "date": "Sat Aug 7 18:17:56 2010 +0200" } */

#include <linux/bio.h>

enum bio_rw_flags dummy = BIO_RW;
