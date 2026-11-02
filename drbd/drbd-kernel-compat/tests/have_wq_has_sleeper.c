/* { "version": "v4.5-rc1", "commit": "1ce0bf50ae2233c7115a18c0c623662d177b434c", "comment": "wq_has_sleeper() moved from net/sock.h to linux/wait.h and takes a wait_queue_head_t instead of a struct socket_wq", "author": "Herbert Xu <herbert@gondor.apana.org.au>", "date": "Thu Nov 26 13:55:39 2015 +0800" } */

#include <linux/wait.h>

#ifndef __same_type
# define __same_type(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))
#endif

bool foo(wait_queue_head_t *wq)
{
	BUILD_BUG_ON(!(__same_type(&wq_has_sleeper, bool (*)(wait_queue_head_t *))));
	return wq_has_sleeper(wq);
}
