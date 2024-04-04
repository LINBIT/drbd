/* { "version": "v6.7", "commit": "e719b4d156749f02eafed31a3c515f2aa9dcc72a", "comment": "introduce bdev_open_by_* functions", "author": "Jan Kara <jack@suse.cz>", "date": "Wed Sep 27 11:34:07 2023 +0200" } */

#include <linux/blkdev.h>

struct bdev_handle *foo(const char *path, blk_mode_t mode, void *holder,
		const struct blk_holder_ops *hops) {
	return bdev_open_by_path(path, mode, holder, hops);
}
