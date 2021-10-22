/* { "version": "v3.14", "commit": "676d23690fb62b5d51ba5d659935e9f7d9da9f8e", "comment": "the len argument was removed", "author": "David S. Miller <davem@davemloft.net>", "date": "Fri Apr 11 16:15:36 2014 -0400" } */
#include <net/sock.h>

#ifndef __same_type
# define __same_type(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))
#endif

void foo_data_ready(struct sock *sk)
{
}

void foo(void)
{
	struct sock sk;

	BUILD_BUG_ON(!(__same_type(sk.sk_data_ready, &foo_data_ready)));
}
