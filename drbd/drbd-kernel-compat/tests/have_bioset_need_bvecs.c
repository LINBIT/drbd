#include <linux/bio.h>

/* The BIOSET_NEED_BVECS enum was introduced with linux-4.14. Before 2.6.12 it
   had 3 parameters as well... */

void dummy(void)
{
	bioset_create(16, 0, BIOSET_NEED_BVECS);
}
