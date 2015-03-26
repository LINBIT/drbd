#include <linux/fs.h>

struct dentry *foo(struct file *f)
{
	return f->f_path.dentry;
}
