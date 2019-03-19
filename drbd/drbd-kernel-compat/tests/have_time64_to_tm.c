#include <linux/time.h>

void foo(void) {
	time64_t t = 0;
	int o = 0;
	struct tm tm;

	time64_to_tm(t, o, &tm);
}
