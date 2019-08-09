/*
 * Because RHEL 7.5 chose to provide refcount.h, but not use it, we don't
 * directly include refcount.h, but rely on the implicit include via kref.h,
 * This way, we avoid compile time warnings about atomic_t != refcount_t.
 */
#include <linux/kref.h>

void test(refcount_t *r)
{
	refcount_inc(r);
}
