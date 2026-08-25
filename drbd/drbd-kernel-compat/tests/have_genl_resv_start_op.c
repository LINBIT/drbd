/* { "version": "v6.1-rc1", "commit": "9c5d03d362519f36cd551aec596388f895c93d2d", "comment": "genetlink: start to validate reserved header bytes", "author": "Jakub Kicinski <kuba@kernel.org>", "date": "Wed Aug 24 17:18:30 2022 -0700" } */
#include <net/genetlink.h>

/* Test that struct genl_family has resv_start_op (v6.1+). Kernels which have
 * it also substitute a reject-all policy for ops at or above it that carry no
 * policy of their own - which is every policy-less op when it is left at 0.
 * Setting it past the last command suppresses that. */
struct genl_family test_family __attribute__((unused)) = {
	.resv_start_op = 1,
};
