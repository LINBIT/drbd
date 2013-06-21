// #include <linux/kernel.h>
#include <linux/blkdev.h>

#ifndef __same_type
# define __same_type(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))
#endif

void dummy(void)
{
	struct block_device_operations ops;
	void (*release) (struct gendisk *, fmode_t);
	BUILD_BUG_ON(!(__same_type(ops.release, release)));
}
