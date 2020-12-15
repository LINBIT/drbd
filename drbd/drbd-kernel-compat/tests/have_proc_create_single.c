/* {"version":"4.17", "commit":"3f3942aca6da351a12543aa776467791b63b3a78", "comment":"With linux v4.17 the timer proc interface got simplified", "author":"Christoph Hellwig <hch@lst.de>", "date":"Tue May 15 15:57:23 2018 +0200"} */
#include <linux/proc_fs.h>

static int foo_seq_show(struct seq_file *seq, void *v)
{
	return 0;
}

struct proc_dir_entry *foo(void)
{
	struct proc_dir_entry *pde;

	pde = proc_create_single("foo", S_IFREG | S_IRUGO , NULL,
				 foo_seq_show);

	return pde;
}
