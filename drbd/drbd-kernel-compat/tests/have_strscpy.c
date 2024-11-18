/* { "version": "v4.2-rc2", "commit": "30035e45753b708e7d47a98398500ca005e02b86", "comment": "strscpy was introduced as a replacement for strlcpy", "author": "Chris Metcalf <cmetcalf@ezchip.com>", "date": "Wed Apr 29 12:52:04 2015 -0400" } */

#include <linux/string.h>

/*
 * For making it compatible with linux-6.12:
 * Work around <linux/compiler.h> defines __must_be_array() and __must_be_cstr() and both expand to
 * BUILD_BUG_ON_ZERO(), but <linux/build_bug.h> defines BUILD_BUG_ON_ZERO(). <linux/compiler.h> does
 * not include <linux/build_bug.h> and Linus does not want that.
 *
 * See https://lore.kernel.org/linux-kernel/20241114101402.156397-1-philipp.reisner@linbit.com/T/#t
 *
 */
#ifndef BUILD_BUG_ON_ZERO
#define BUILD_BUG_ON_ZERO(e) ((int)(sizeof(struct { int:(-!!(e)); })))
#endif

ssize_t foo(char *dest, const char *src, size_t count)
{
	return strscpy(dest, src, count);
}
