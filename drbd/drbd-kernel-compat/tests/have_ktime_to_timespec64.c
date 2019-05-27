#include <linux/ktime.h>

void foo(void) {
	ktime_t kt = 0;
	ktime_to_timespec64(kt);
}
