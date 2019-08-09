/* { "version": "v4.8", "commit": "28a8f0d317bf225ff15008f5dd66ae16242dd843", "comment": "REQ_FLUSH got renamed to REQ_PREFLUSH", "author": "Mike Christie <mchristi@redhat.com>", "date": "Sun Jun 5 14:32:25 2016 -0500" } */
#include <linux/blk_types.h>

int dummy = REQ_PREFLUSH;
