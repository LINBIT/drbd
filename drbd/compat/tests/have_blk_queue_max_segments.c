#include <linux/blkdev.h>

#ifndef blk_queue_max_segments
void *p = blk_queue_max_segments;
#endif
