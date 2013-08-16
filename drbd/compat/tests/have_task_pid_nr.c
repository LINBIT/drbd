#include <linux/sched.h>

int main(void)
{
	pid_t p = task_pid_nr(current);

	return (int)p;
}
