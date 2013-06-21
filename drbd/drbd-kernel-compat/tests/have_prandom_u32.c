#include <linux/random.h>

int main(void)
{
	u32 r = prandom_u32();
	return 0;
}
