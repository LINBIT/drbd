#include <net/genetlink.h>

void test(void)
{
	struct genl_family family = { };
	struct genl_ops ops[23];

	genl_register_family_with_ops(&family, ops);
}
