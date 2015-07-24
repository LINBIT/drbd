#include <linux/backing-dev.h>


/* With commit 4452226 (linux v4.2)
   BDI_async_congested was renamed to WB_async_congested and
   BDI_sync_congested was renamed to WB_sync_congested.
   */

void foo(void)
{
	int a = WB_async_congested;
	int b = WB_sync_congested;
}
