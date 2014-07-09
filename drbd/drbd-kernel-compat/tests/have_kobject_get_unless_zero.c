#include <linux/kobject.h>

void dummy(void)
{
	if (!kobject_get_unless_zero(NULL))
		return;
}
