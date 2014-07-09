#include <linux/kref.h>

void dummy(void)
{
	if (!kref_get_unless_zero(NULL))
		return;
}
