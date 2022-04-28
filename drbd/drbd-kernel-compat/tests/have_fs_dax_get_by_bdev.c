/* { "version": "v4.13-rc7", "commit": "78f35473508118df5ea04b9515ac3f1aaec0a980", "comment": "fs_dax_get_by_bdev was introduced", "author": "Dan Williams <dan.j.williams@intel.com>", "date": "Wed Aug 30 09:16:38 2017 -0700" } */

#include <linux/blkdev.h>
#include <linux/dax.h>

void *x = fs_dax_get_by_bdev;
