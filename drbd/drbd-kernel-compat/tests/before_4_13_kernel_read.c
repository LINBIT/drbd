#include <linux/fs.h>

#ifndef __same_type
# define __same_type(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))
#endif

ssize_t kernel_read_since_4_13(struct file *file, void *buf, size_t count, loff_t *pos);
int kernel_read_before_4_13(struct file *file, loff_t offset, char *addr, unsigned long count);


int foo(void)
{
	struct file *file = NULL;
	loff_t offset = 0;
	char *addr = NULL;
	unsigned long count = 0;

	BUILD_BUG_ON(!(__same_type(kernel_read_before_4_13, kernel_read)));
	return kernel_read(file, offset, addr, count);
}
