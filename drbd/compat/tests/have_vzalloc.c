#include <linux/vmalloc.h>

void foo(void)
{
	void *v = vzalloc(8);
}
