#include <linux/dcache.h>

static inline struct inode *d_inode(const struct dentry *dentry)
{
	return dentry->d_inode;
}
