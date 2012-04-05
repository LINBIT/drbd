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

void foo(void)
{
	struct request_queue *q = NULL;
	blk_queue_make_request(q, drbd_make_request);
	BUILD_BUG_ON(!(__same_type(drbd_make_request, make_request_fn)));
}
