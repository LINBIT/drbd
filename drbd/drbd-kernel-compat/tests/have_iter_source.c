/* { "version": "v6.2-rc1", "commit": "de4eda9de2d957ef2d6a8365a01e26a435e958cb", "comment": "iov_iter direction initializers ITER_SOURCE/ITER_DEST were added", "author": "Al Viro <viro@zeniv.linux.org.uk>", "date": "Thu Sep 15 20:25:47 2022 -0400" } */

#include <linux/uio.h>

int foo(void)
{
	return ITER_SOURCE;
}
