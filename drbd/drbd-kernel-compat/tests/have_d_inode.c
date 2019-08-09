#include <linux/dcache.h>

struct inode *foo(struct dentry *dentry)
{
	return d_inode(dentry);
}
