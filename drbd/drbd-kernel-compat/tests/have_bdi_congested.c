/* { "version": "v5.18-rc1", "commit": "b9b1335e640308acc1b8f26c739b804c80a6c147", "comment": "In 5.18, inode_congested() and all its related functions were removed because 'No bdi reports congestion any more'", "author": "NeilBrown <neilb@suse.de>", "date": "Tue Mar 22 14:39:10 2022 -0700" } */

#include <linux/backing-dev.h>

int foo(struct backing_dev_info *bdi, int cong_bits)
{
	return bdi_congested(bdi, cong_bits);
}
