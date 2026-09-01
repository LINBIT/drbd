/* { "version": "v5.10-rc1", "commit": "48526a0f4ca2b484cab4318dc0b2c2be1d8685b7", "comment": "genetlink: bring back per op policy - this also added the per-op maxattr; before v5.2 struct genl_ops has .policy but no .maxattr", "author": "Jakub Kicinski <kuba@kernel.org>", "date": "Fri Oct 2 14:49:57 2020 -0700" } */
#include <net/genetlink.h>

struct genl_ops ops = { .maxattr = 1, };
