#include "drbd_wrappers.h"

#ifndef COMPAT_HAVE_PROC_CREATE_SINGLE
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
/* This compat wrapper is not generic, only good enough for DRBD */
extern int drbd_seq_show(struct seq_file *seq, void *v);

static int drbd_proc_single_open(struct inode *inode, struct file *file)
{
	return single_open(file, drbd_seq_show, NULL);
}

struct proc_dir_entry *proc_create_single(const char *name, umode_t mode,
		struct proc_dir_entry *parent,
		int (*show)(struct seq_file *, void *))
{
	static const struct file_operations drbd_proc_single_fops = {
		.open           = drbd_proc_single_open,
		.read           = seq_read,
		.llseek         = seq_lseek,
		.release        = single_release,
	};

	return proc_create_data(name, mode, parent, &drbd_proc_single_fops, NULL);
}
#endif
