#include <linux/timer.h>

/* With linux v4.16 the timer interface changed */

void timer_fn(struct timer_list *t)
{
}

void foo(void)
{
	struct timer_list timer;

	timer_setup(&timer, timer_fn, 0);
}
