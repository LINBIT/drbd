/* { "version": "v4.11-rc2", "commit": "c440408cf6901eeb2c09563397e24a9097907078", "comment": "get_random_int was renamed to get_random_u32", "author": "Jason A. Donenfeld <Jason@zx2c4.com>", "date": "Sun Jan 22 16:34:08 2017 +0100" } */

#include <linux/prandom.h>

u32 foo(void)
{
	return get_random_u32();
}
