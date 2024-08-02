/* Tests show older kernels sometimes fails to clear TIF_SIGPENDING
 * when repeatedly calling drbd_open() when the first invocation
 * returned -ERESTARTSYS because of a pending signal. */

#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,14,0)
#error No need to call recalc sigpending in drbd_open()
#endif
