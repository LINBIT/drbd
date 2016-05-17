#include <crypto/hash.h>

void foo(void)
{
	struct crypto_shash tfm;
	SHASH_DESC_ON_STACK(desc, &tfm);
}
