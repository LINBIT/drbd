#include <linux/drbd.h>
#include <linux/kernel.h>

#define SZO(type,size) \
	s = sizeof(type); \
	if (s != size) { \
		printk("<3>sizeof(" #type "): %d != %d\n", s, size); \
		err = -1; \
	}

int sizeof_drbd_structs_sanity_check(void)
{
	int err = 0, s = 0;
	SZO(struct disk_config,		 32)
	SZO(struct net_config,		448)
	SZO(struct syncer_config,	 24)
	SZO(struct ioctl_disk_config,	 40)
	SZO(struct ioctl_net_config,	456)
	SZO(struct ioctl_syncer_config,	 32)
	SZO(struct ioctl_wait,		 16)
	SZO(struct ioctl_get_config,	580)
	SZO(struct ioctl_get_uuids,      48)
	if (err) printk("<3>ioctls won't work, aborting\n");
	return err;
}
