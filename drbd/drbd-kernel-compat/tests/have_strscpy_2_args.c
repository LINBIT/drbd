/* { "version": "v6.9-rc1", "commit": "e6584c3964f2ff76a9fb5a701e4a59997b35e547", "comment": "strscpy() gained a 2-argument form that infers the destination size", "author": "Kees Cook <keescook@chromium.org>", "date": "Wed Sep 20 12:38:14 2023 -0700" } */
#include <linux/string.h>

void foo(void)
{
	char dst[16];

	strscpy(dst, "test");
}
