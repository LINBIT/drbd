#include <crypto/hash.h>

void foo(void)
{
	void (*p)(struct shash_desc *) = shash_desc_zero;
}
