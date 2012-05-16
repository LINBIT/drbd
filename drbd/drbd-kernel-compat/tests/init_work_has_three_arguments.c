#include <linux/workqueue.h>

void f(void)
{
	struct work_struct ws;
	INIT_WORK(&ws, NULL, NULL);
}
