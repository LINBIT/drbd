#include <linux/fs.h>

struct inode *foo(struct file *filp)
{
	return file_inode(filp);
}
