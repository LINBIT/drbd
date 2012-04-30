#include <linux/vmalloc.h>

void foo()
{
	void *v = vzalloc(8);
}
