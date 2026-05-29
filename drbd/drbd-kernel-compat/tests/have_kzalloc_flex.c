/* {"version": "v7.0-rc1", "commit": "e4c8b46b924eb8de66c6f0accc9cdd0c2e8fa23b", "comment": "kzalloc_flex was added as a type-safe wrapper for allocating structs with a flexible array member", "author": "Kees Cook <kees@kernel.org>", "date": "Wed Dec 3 15:30:34 2025 -0800"} */
#include <linux/slab.h>

struct foo_flex {
	int n;
	int values[];
};

void *foo(void)
{
	return kzalloc_flex(struct foo_flex, values, 2, GFP_KERNEL);
}
