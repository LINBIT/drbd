#include <linux/fs.h>

#ifdef CONFIG_SYSFS
void dummy(struct block_device *bdev, void *holder, struct gendisk *disk)
{
	bd_claim_by_disk(bdev, holder, disk);
}
#endif
