/* { "version": "v6.1-rc6", "commit": "7f576b2593a978451416424e75f69ad1e3ae4efe", "comment": "get_random_u32_below was added", "author": "Jason A. Donenfeld <Jason@zx2c4.com>", "date": "Wed Oct 19 23:19:35 2022 -0600" } */

#include <linux/random.h>

u32 foo(u32 i)
{
	return get_random_u32_below(i);
}
