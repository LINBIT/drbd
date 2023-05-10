/* { "version": "v6.2-rc1", "commit": "f571faf6e443b6011ccb585d57866177af1f643c", "comment": "timer_shutdown was added", "author": "Thomas Gleixner <tglx@linutronix.de>", "date": "Wed Nov 23 21:18:53 2022 +0100" } */

#include <linux/timer.h>

int foo(struct timer_list *t)
{
	return timer_shutdown(t);
}
