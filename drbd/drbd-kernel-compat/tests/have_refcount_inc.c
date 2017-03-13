#include <linux/refcount.h>

void test(refcount_t *r)
{
	refcount_inc(r);
}
