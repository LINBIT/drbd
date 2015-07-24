#include <linux/dcache.h>

/* Since dc3f4198e (linux v4.2) simple_positive is accessible for modules */

void foo(void)
{
	int r = simple_positive((struct dentry *)NULL);
}
