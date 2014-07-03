#include <linux/types.h>
#include <linux/random.h>

int main(void)
{
	u32 r = prandom_u32();
	return r;
}
