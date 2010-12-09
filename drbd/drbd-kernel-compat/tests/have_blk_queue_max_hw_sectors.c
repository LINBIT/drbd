#include <linux/blkdev.h>

#ifndef blk_queue_max_hw_sectors
void *p = blk_queue_max_hw_sectors;
#endif
