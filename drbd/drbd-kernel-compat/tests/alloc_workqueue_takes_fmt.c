/* {"version": "3.3", "commit": "b196be89cdc14a88cc637cdad845a75c5886c82d", "comment": Since Linux 3.3, alloc_workqueue takes printf-style fmt and args arguments", "author": "Tejun Heo <tj@kernel.org>", "date": "Tue Jan 10 15:11:35 2012 -0800" } */
#include <linux/workqueue.h>

void dummy(void)
{
	alloc_workqueue("%u", 0, 0, 0);
}
