/* { "version": "v6.13-rc7", "commit": "f7862dfef6612b87b2ad8352c4d73886f09456d6", "comment": "debugfs_chnage_name() replaces debugfs_rename()", "author": "Al Viro <viro@zeniv.linux.org.uk>", "date": "Sun Jan 12 08:07:05 2025 +0000" } */

#include <linux/debugfs.h>

int foo(const char *s);
int foo(const char *s)
{
	return debugfs_change_name(NULL, "%s", s);
}
