#include <linux/mm.h>

void foo(void) {
	kvfree(NULL);
}
