#include <linux/debugfs.h>

struct dentry *dummy(void)
{
	return debugfs_create_symlink("dummy", NULL, "dummy2");
}
