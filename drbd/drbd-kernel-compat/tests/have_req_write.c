/* { "version": "v2.6.36", "commit": "7b6d91daee5cac6402186ff224c3af39d79f4a0e", "comment": "REQ_RW was unified into REQ_WRITE etc", "author": "Christoph Hellwig <hch@lst.de>", "date": "Sat Aug 7 18:20:39 2010 +0200" } */

#include <linux/bio.h>

enum rq_flag_bits dummy = REQ_WRITE;
