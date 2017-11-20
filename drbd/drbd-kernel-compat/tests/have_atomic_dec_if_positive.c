#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,37)
#include <linux/atomic.h>
#else
#include <asm/atomic.h>
#endif

int foo(atomic_t *a)
{
	return atomic_dec_if_positive(a);
}
