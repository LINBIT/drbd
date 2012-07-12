#include <linux/highmem.h>
/* see 980c19e3
 * highmem: mark k[un]map_atomic() with two arguments as deprecated */
void *f(void)
{
	return kmap_atomic(NULL);
}
