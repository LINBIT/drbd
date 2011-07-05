#include <asm/system.h>
/* Including asm/system.h is necessary for s390.

   They define smp_mb__before_clear_bit() in asm/system.h
   From asm/bitops.h they include asm-generic/bitops/lock.h
   The macro defining clear_bit_unlock() in
   asm-generic/bitops/lock.h needs smp_mb__before_clear_bit().

   They fail to include asm/system.h from asm/bitops.h
*/
#include <linux/bitops.h>

void foo()
{
	unsigned long bar;

	clear_bit_unlock(0, &bar);
}
