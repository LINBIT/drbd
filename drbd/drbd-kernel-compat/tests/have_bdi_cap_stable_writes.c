/* { "version": "v3.9-rc1", "commit": "7d311cdab663f4f7ab3a4c0d5d484234406f8268", "comment": "BDI_CAP_STABLE_WRITES was introduced as a backing_dev_info flag", "author": "Darrick J. Wong <darrick.wong@oracle.com>", "date": "Thu Feb 21 16:42:48 2013 -0800" } */

#include <linux/backing-dev.h>

int foo(void)
{
	return BDI_CAP_STABLE_WRITES;
}
