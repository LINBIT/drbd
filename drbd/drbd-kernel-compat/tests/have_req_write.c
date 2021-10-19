/* { "version": "v4.8-rc1", "commit": "4e1b2d52a80d79296a5d899d73249748dea71a53", "comment": "REQ_WRITE was removed, having been added in 7b6d91daee5ca (v2.6.36)", "author": "Mike Christie <mchristi@redhat.com>", "date": "Sun Jun 5 14:32:22 2016 -0500" } */

#include <linux/bio.h>

enum rq_flag_bits dummy = REQ_WRITE;
