#include <linux/bitops.h>

void foo()
{
	unsigned long bar;

	clear_bit_unlock(0, &bar);
}
