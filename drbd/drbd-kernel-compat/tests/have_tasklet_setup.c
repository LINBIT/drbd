/* { "version": "v5.9-rc1", "commit": "12cc923f1ccc1df467e046b02a72c2b3b321b6a2", "comment": "tasklet: Introduce new initialization API", "author": "Romain Perier <romain.perier@gmail.com>", "date": "Sun Sep 29 18:30:13 2019 +0200" } */
#include <linux/interrupt.h>

void callback(struct tasklet_struct *t)
{
}

void foo(void)
{
	struct tasklet_struct t;

	tasklet_setup(&t, callback);
}
