#include <linux/mm.h>
#include <linux/slab.h>

void foo(void) {
	kvfree(NULL);
}
