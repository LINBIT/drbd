/* { "version": "v4.15", "commit": "9fa68f620041be04720d0cbfb1bd3ddfc6310b24", "comment": "The ability to check whether or not an shash algorithm requires a key was added in 4.15", "author": "Eric Biggers <ebiggers@google.com>", "date": "Wed Jan 3 11:16:27 2018 -0800" } */

#include <linux/crypto.h>

int foo(void)
{
	return CRYPTO_TFM_NEED_KEY;
}
