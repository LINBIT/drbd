#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39)
#include <linux/genhd.h>

#ifndef __same_type
# define __same_type(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))
#endif

static struct hd_struct hd;
void dummy(void)
{
	BUILD_BUG_ON(!__same_type(atomic_t, hd.in_flight[0]));
}
#endif
