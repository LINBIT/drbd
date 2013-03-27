#include <linux/idr.h>

void foo(void)
{
	struct idr idr;
	struct bar *b;
	int i;

	idr_for_each_entry(&idr, b, i)
		;
}
