/* {"version":"4.17", "commit": "610b15c50e86eb1e4b77274fabcaea29ac72d6a8", "comment": "Since Linux 4.17, struct_size should be used to get the size of a struct with a trailing array", "author": "Kees Cook <keescook@chromium.org>", "date": "Mon May 7 16:47:02 2018 -0700" } */
#include <linux/module.h>
#include <linux/overflow.h>

struct x {
	int some;
	int values[];
};

void foo(void)
{
	struct x *p;
	struct_size(p, values, 1);
}
