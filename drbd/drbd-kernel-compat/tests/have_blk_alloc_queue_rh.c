/* { "version": "4.18.0-277.el8" } */

#include <linux/blkdev.h>

struct request_queue *foo(make_request_fn *fn)
{
	return blk_alloc_queue_rh(fn, NUMA_NO_NODE);
}
