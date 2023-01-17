/* { "version": "v3.14-rc1", "commit": "f337db64af059c9a94278a8b0ab97d87259ff62f", "comment": "prandom_u32_max was added", "author": "Daniel Borkmann <dborkman@redhat.com>", "date": "Wed Jan 22 02:29:39 2014 +0100" } */

#include <linux/prandom.h>

u32 foo(u32 i)
{
	return prandom_u32_max(i);
}
