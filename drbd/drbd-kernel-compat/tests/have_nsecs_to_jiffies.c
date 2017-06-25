#include <linux/jiffies.h>

unsigned long foo_bar(u64 n)
{
	return nsecs_to_jiffies(n);
}
