#include <linux/idr.h>

void foo(void)
{
	struct idr *idr = NULL;
	idr_is_empty(idr);
}
