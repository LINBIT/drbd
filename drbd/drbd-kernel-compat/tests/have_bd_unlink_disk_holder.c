#include <linux/genhd.h>
#include <linux/fs.h>
#include <linux/blkdev.h>

#ifdef CONFIG_SYSFS
void dummy(struct block_device *bdev, struct gendisk *disk)
{
	/* also check that we are not between 49731ba and e09b457,
	 * where there was a singular bd_holder_disk for a short time */
	if (!list_empty(&bdev->bd_holder_disks))
		bd_unlink_disk_holder(bdev, disk);
}
#endif
