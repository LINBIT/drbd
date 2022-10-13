/* Cheap heuristic: just assume every kernel below 5.0 needs drbd_wrappers.h.
 * This is obviously not really right, but it doesn't hurt if we include it on
 * a kernel that does not need it.
 * The only thing we care about: we don't want (and don't need) drbd_wrappers.h
 * on "modern" kernels.
 */

#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,0,0)
#error drbd_wrappers.h not required
#endif
