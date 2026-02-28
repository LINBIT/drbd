/* { "version": "v6.2-rc1", "commit": "20b0b53aca436af9fece9428ca3ab7c7b9cf4583", "comment": "genetlink: introduce split op representation", "author": "Jakub Kicinski <kuba@kernel.org>", "date": "Fri Nov 4 12:13:33 2022 -0700" } */
#include <net/genetlink.h>

/* Test that pre_doit uses genl_split_ops (v6.2+), not genl_ops */
int foo(const struct genl_split_ops *ops,
	struct sk_buff *skb, struct genl_info *info)
{
	return 0;
}

struct genl_family test_family __attribute__((unused)) = {
	.pre_doit = foo,
};
