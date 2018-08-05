#include <linux/proc_fs.h>
/*
With linux v4.17 the timer proc interface got simplified
commit 3f3942aca6da351a12543aa776467791b63b3a78
Author: Christoph Hellwig <hch@lst.de>
Date:   Tue May 15 15:57:23 2018 +0200
*/

static int foo_seq_show(struct seq_file *seq, void *v)
{
}

struct proc_dir_entry *foo(void)
{
	struct proc_dir_entry *pde;

	pde = proc_create_single("foo", S_IFREG | S_IRUGO , NULL,
				 foo_seq_show);

	return pde;
}
