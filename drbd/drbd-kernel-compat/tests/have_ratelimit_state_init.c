#include <linux/ratelimit.h>

int main(void)
{
	struct ratelimit_state rs;
	ratelimit_state_init(&rs, 5 * HZ, 10);

	return 0;
}
