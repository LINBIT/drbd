#include <linux/fs.h>

void foo(void)
{
	struct inode *inode = NULL;

	inode_lock(inode);
}
