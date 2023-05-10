/* { "version": "v4.2-rc2", "commit": "30035e45753b708e7d47a98398500ca005e02b86", "comment": "strscpy was introduced as a replacement for strlcpy", "author": "Chris Metcalf <cmetcalf@ezchip.com>", "date": "Wed Apr 29 12:52:04 2015 -0400" } */

#include <linux/string.h>

ssize_t foo(char *dest, const char *src, size_t count)
{
	return strscpy(dest, src, count);
}
