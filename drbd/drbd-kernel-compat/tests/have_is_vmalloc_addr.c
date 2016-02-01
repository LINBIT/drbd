#include <linux/mm.h>

void foo(void) {
	is_vmalloc_addr(NULL);
}
