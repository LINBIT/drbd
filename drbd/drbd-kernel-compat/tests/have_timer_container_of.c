/* { "version": "v6.16-rc1", "commit": "41cb08555c4164996d67c78b3bf1c658075b75f1", "comment": "from_timer renamed to timer_container_of", "author": "Ingo Molnar <mingo@kernel.org>", "date": "Fri May 9 07:51:14 2025 +0200" } */

#include <linux/timer.h>

struct bar
{
	struct timer_list timer;
};

void foo(struct timer_list *t)
{
	struct bar *b = timer_container_of(b, t, timer);
}
