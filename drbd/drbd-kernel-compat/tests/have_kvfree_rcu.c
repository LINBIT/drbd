/* { "version": "v5.9-rc1", "commit": "1835f475e3518ade61e25a57572c78b953778656", "comment": "The single-argument version of kvfree_rcu was added", "author": "Uladzislau Rezki (Sony) <urezki@gmail.com>", "date": "Mon May 25 23:47:59 2020 +0200" } */

#include <linux/rcupdate.h>

void foo(void *ptr)
{
	kvfree_rcu(ptr);
}
