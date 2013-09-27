#include <linux/genetlink.h>

/* genl_lock() is exported for modules since 2.6.34 */

void foo(void)
{
	void (*genl_lock_ptr)(void);

	genl_lock_ptr = genl_lock;
}
