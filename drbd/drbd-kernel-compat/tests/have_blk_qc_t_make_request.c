#include <linux/blkdev.h>

/* hm. sometimes this pragma is ignored :(
 * use BUILD_BUG_ON instead.
#pragma GCC diagnostic warning "-Werror"
 */

/* in Commit dece16353ef47d8d33f5302bc158072a9d65e26f
   make_request() becomes type blk_qc_t. Before it had type void, before that int.
 */

blk_qc_t drbd_make_request(struct request_queue *q, struct bio *bio)
{
	return BLK_QC_T_NONE;
}

#ifndef __same_type
# define __same_type(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))
#endif

void foo(void)
{
	BUILD_BUG_ON(!(__same_type(drbd_make_request, make_request_fn)));
}
