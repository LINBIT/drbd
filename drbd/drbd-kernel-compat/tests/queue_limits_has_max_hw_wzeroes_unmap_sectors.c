/* { "version": "v6.17-rc1", "commit": "0c40d7cb5ef3af260e8c7f88e0e5d7ae15d6ce57", "comment": "max_hw_wzeroes_unmap_sectors introduced", "author": "Zhang Yi <yi.zhang@huawei.com>", "date": "Thu Jun 19 19:17:58 2025 +0800" } */

#include <linux/blkdev.h>

int foo(struct queue_limits *lim)
{
	return lim->max_hw_wzeroes_unmap_sectors;
}
