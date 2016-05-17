#include <crypto/hash.h>

void foo(void)
{
	struct crypto_ahash tfm;
	AHASH_REQUEST_ON_STACK(desc, &tfm);
}
