#include <linux/drbd.h>
#include <linux/linkage.h>

/* from linux/kernel.h */
asmlinkage int printk(const char * fmt, ...)
	__attribute__ ((format (printf, 1, 2)));

#define SZO(type,size) \
	if (sizeof(type) != size) { \
		printk("<3>sizeof(" #type ") != %d; " \
			"ioctls won't work, aborting\n", size); \
		return -1; \
	}

int sizeof_drbd_structs_sanity_check(void)
{
	SZO(struct disk_config,		 24)
	SZO(struct net_config,		300)
	SZO(struct syncer_config,	 20)
	SZO(struct ioctl_disk_config,	 28)
	SZO(struct ioctl_net_config,	304)
	SZO(struct ioctl_syncer_config,	 24)
	SZO(struct ioctl_wait,		 12)
	SZO(struct ioctl_get_config,	428)
	return 0;
}
