/* { "version": "v4.0-rc1", "commit": "536fa402221f09633e7c5801b327055ab716a363", "comment": "smp_load_acquire() and smp_store_release() accept 1- and 2-byte types", "author": "Paul E. McKenney <paulmck@linux.vnet.ibm.com>", "date": "Fri Sep 5 11:14:48 2014 -0700" } */

#include <linux/compiler.h>
#include <asm/barrier.h>

bool foo(bool *p)
{
	smp_store_release(p, true);
	return smp_load_acquire(p);
}
