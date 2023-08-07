/* { "version": "v5.0-rc1", "commit": "76ef5e17252789da79db78341851922af0c16181", "comment": "keys: Export lookup_user_key to external users", "author": "Dave Jiang <dave.jiang@intel.com>", "date": "Tue Dec 4 10:31:27 2018 -0800" } */
#include <linux/key.h>

key_ref_t foo(void)
{
	return lookup_user_key(0, 0, 0);
}
