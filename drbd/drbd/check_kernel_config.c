// kernel version and config test code
// preprocessor only

#include <linux/version.h>
#include <linux/autoconf.h>

#define drbd_ok
#ifndef CONFIG_PROC_FS
#warning You need to configure the kernel with procfs support.
#undef drbd_ok
#endif
#ifndef CONFIG_MODULES
#warning You need to configure the kernel with module support.
#undef drbd_ok
#endif
#ifdef CONFIG_BLK_DEV_NBD
#warning You must not configure NBD support into the kernel. NBD module is ok.
#undef drbd_ok
#endif

#ifdef drbd_ok
drbd_configured_kernver UTS_RELEASE
#endif
