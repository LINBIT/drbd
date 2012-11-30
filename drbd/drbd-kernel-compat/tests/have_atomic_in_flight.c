#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39)
#include <linux/genhd.h>

static struct hd_struct hd;
void dummy(void)
{
	atomic_inc(&hd.in_flight[0]);
}
#endif
