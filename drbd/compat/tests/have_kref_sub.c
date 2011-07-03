#include <linux/kref.h>

void test(void)
{
	struct kref kref = { };

	kref_sub(&kref, 2, NULL);
}
