/* { "version": "v6.4", "commit": "dd06e72e68bcb4070ef211be100d2896e236c8fb", "comment": "add __counted_by macro", "author": "Kees Cook <keescook@chromium.org>", "date": "Wed May 17 12:08:44 2023 -0700" } */

#include <linux/compiler_attributes.h>

struct foo {
	int a;
	int b[] __counted_by(a);
};
