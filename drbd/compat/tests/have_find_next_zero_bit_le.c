#include <linux/stddef.h>
#include <linux/bitops.h>

unsigned long func(void)
{
	void *addr;
	unsigned long size, offset;

	addr = NULL;
	size = 0;
	offset = 0;
	return find_next_zero_bit_le(addr, size, offset);
}
