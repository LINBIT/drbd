#include <linux/kref.h>

void foo(void)
{
	struct kref t;

	kref_sub(&t, 2, NULL);
}
