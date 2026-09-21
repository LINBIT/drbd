/* {"version": "4.15-rc1", "commit": "5307e2ad69ab3b0e0622fdf8b254c1d4565eb924", "comment": "assign_bit() was introduced as a helper to set or clear a bit depending on a boolean value", "author": "Lukas Wunner <lukas@wunner.de>", "date": "Thu Oct 12 12:40:10 2017 +0200"} */
#include <linux/bitops.h>

void dummy(unsigned long *addr, bool value)
{
	assign_bit(0, addr, value);
}
