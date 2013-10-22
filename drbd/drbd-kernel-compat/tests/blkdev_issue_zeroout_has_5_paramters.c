#include <linux/blkdev.h>

/* In 2.6.34 and 2.6.35 this function had 5 parameters. Later the
   flags parameter was dropped */

int foo()
{
	int r;
	r = blkdev_issue_zeroout(NULL, 0, 0, 0, BLKDEV_IFL_WAIT);
}
