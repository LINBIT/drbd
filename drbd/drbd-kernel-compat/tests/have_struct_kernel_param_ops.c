/* {"version":"2.6.36", "commit": "9bbb9e5a33109b2832e2e63dcc7a132924ab374b", "comment": "Since Linux 2.6.36, modules use struct kernel_param_ops to define their parameters", "author": "Rusty Russell <rusty@rustcorp.com.au>", "date": "Wed Aug 11 23:04:12 2010 -0600" } */
#include <linux/moduleparam.h>

int main(void)
{
	struct kernel_param_ops ops = {};

	return 0;
}
