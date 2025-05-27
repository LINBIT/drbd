/* { "version": "v6.1-rc3", "commit": "6e4068a11413b96687a03c39814539e202de294b", "comment": "mempool: introduce mempool_is_saturated", "author": "Pavel Begunkov <asml.silence@gmail.com>", "date": "Wed Nov 2 15:18:19 2022 +0000" } */

#include <linux/mempool.h>

bool foo(mempool_t *pool)
{
	return mempool_is_saturated(pool);
}
