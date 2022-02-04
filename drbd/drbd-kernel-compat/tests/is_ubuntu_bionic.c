#include <generated/utsrelease.h>
#include <linux/version.h>

#if defined(UTS_UBUNTU_RELEASE_ABI) && LINUX_VERSION_CODE > KERNEL_VERSION(4,15,0) && LINUX_VERSION_CODE < KERNEL_VERSION(4,16,0)
/* "This is an Ubuntu Bionic kernel" */
#else
#error not an Ubuntu Bionic kernel
#endif
