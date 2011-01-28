#include <linux/blkdev.h>

#ifndef blk_queue_max_hw_sectors
void *p = blk_queue_max_hw_sectors;
#endif

/* For kernel versions 2.6.31 to 2.6.33 inclusive, even though
 * blk_queue_max_hw_sectors is present, we actually need to use
 * blk_queue_max_sectors to set max_hw_sectors. :-(
 * RHEL6 2.6.32 chose to be different and already has eliminated
 * blk_queue_max_sectors as upstream 2.6.34 did.
 */
#ifndef blk_queue_max_sectors
void *q = blk_queue_max_sectors;
#endif
