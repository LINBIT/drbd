#include <linux/proc_fs.h>

int main(void)
{
	struct inode *inode = NULL;
	void *data;

	data = PDE_DATA(inode);
	return 0;
}
