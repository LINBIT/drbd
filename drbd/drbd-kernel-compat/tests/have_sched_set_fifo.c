/* { "version": "v5.8-rc2", "commit": "7318d4cc14c8c8a5dde2b0b72ea50fd2545f0b7a", "comment": "sched_set_fifo was introduced, replacing sched_setscheduler and friends", "author": "Peter Zijlstra <peterz@infradead.org>", "date": "Tue Apr 21 12:09:13 2020 +0200" } */

#include <linux/sched.h>

void foo(struct task_struct *p)
{
	sched_set_fifo(p);
}
