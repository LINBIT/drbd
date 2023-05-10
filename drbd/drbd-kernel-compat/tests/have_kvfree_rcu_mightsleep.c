/* { "version": "v6.3-rc1", "commit": "608723c41cd951fb32ade2f8371e61c270816175", "comment": "kvfree_rcu_mightsleep was added", "author": "Uladzislau Rezki (Sony) <urezki@gmail.com>", "date": "Wed Feb 1 16:08:07 2023 +0100" } */

#include <linux/rcupdate.h>

void foo(void *ptr)
{
	kvfree_rcu_mightsleep(ptr);
}
