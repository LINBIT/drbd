/* { "version": "v6.15", "commit": "8fa7292fee5c5240402371ea89ab285ec856c916", "comment": "timer_delete introduced", "author": "Thomas Gleixner <tglx@linutronix.de>", "date": "Sat Apr 5 10:17:26 2025 +0200" } */

#include <linux/timer.h>

int foo(struct timer_list *t)
{
	return timer_delete(t);
}
