#include <linux/fs.h>
#include <linux/blkdev.h>

#ifdef CONFIG_SYSFS
void dummy(struct block_device *bdev, struct gendisk *disk)
{
	bd_unlink_disk_holder(bdev, disk);
}
#endif
