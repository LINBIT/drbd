#include <linux/blkdev.h>

/* hm. sometimes this pragma is ignored :(
 * use BUILD_BUG_ON instead.
#pragma GCC diagnostic warning "-Werror"
 */

/* in Commit 5a7bbad27a410350e64a2d7f5ec18fc73836c14f (between Linux-3.1 and 3.2)
   make_request() becomes type void. Before it had type int.
 */

void drbd_make_request(struct request_queue *q, struct bio *bio)
{
}

#ifndef __same_type
# define __same_type(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))
#endif

void foo(void)
{
	BUILD_BUG_ON(!(__same_type(drbd_make_request, make_request_fn)));
}
