#include <asm/atomic.h>

int foo(atomic_t *a)
{
	return atomic_dec_if_positive(a);
}
