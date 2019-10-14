#include <linux/blkdev.h>

struct my_plug_cb {
	struct blk_plug_cb cb;
	int bar;
};


static void drbd_compat_test_unplug_fn(struct blk_plug_cb *cb, bool from_schedule)
{
}

void foo(void)
{
	struct blk_plug_cb *plug;

	plug = blk_check_plugged(drbd_compat_test_unplug_fn, NULL, sizeof(struct my_plug_cb));
}
