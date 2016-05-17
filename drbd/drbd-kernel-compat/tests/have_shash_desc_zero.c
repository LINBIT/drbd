#include <crypto/hash.h>

void foo(void)
{
	void (*p1)(struct ahash_request *) = ahash_request_zero;
	void (*p2)(struct shash_desc *) = shash_desc_zero;
}
