/* { "version": "v4.7-rc3", "commit": "f21508211d2b16e65821abd171378fa6ece126fe", "comment": "REQ_OPs were introduced", "author": "Mike Christie <mchristi@redhat.com>", "date": "Sun Jun 5 14:31:42 2016 -0500" } */
#include <linux/blk_types.h>

int dummy = REQ_OP_WRITE;
