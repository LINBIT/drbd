#include <linux/fs.h>

void foo(void) {
	submit_bio(0,NULL);
}
