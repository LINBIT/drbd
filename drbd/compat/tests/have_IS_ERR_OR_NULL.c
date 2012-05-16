#include <linux/err.h>

int foo(void)
{
	void *x = 0;

	return IS_ERR_OR_NULL(x);
}
