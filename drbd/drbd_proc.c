/*
   drbd_proc.c

   This file is part of DRBD by Philipp Reisner and Lars Ellenberg.

   Copyright (C) 2001-2008, LINBIT Information Technologies GmbH.
   Copyright (C) 1999-2008, Philipp Reisner <philipp.reisner@linbit.com>.
   Copyright (C) 2002-2008, Lars Ellenberg <lars.ellenberg@linbit.com>.

   drbd is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   drbd is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with drbd; see the file COPYING.  If not, write to
   the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.

 */

#include <linux/module.h>

#include <asm/uaccess.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/drbd.h>
#include "drbd_int.h"
#include <drbd_transport.h>

static int drbd_proc_open(struct inode *inode, struct file *file);
static int drbd_proc_release(struct inode *inode, struct file *file);

struct proc_dir_entry *drbd_proc;
const struct file_operations drbd_proc_fops = {
	.owner		= THIS_MODULE,
	.open		= drbd_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= drbd_proc_release,
};

static int drbd_seq_show(struct seq_file *seq, void *v)
{
	seq_printf(seq, "version: " REL_VERSION " (api:%d/proto:%d-%d)\n%s\n",
		   GENL_MAGIC_VERSION, PRO_VERSION_MIN, PRO_VERSION_MAX, drbd_buildtag());

	print_kref_debug_info(seq);

	drbd_print_transports_loaded(seq);

	return 0;
}

static int drbd_proc_open(struct inode *inode, struct file *file)
{
	int err;

	if (try_module_get(THIS_MODULE)) {
		err = single_open(file, drbd_seq_show, NULL);
		if (err)
			module_put(THIS_MODULE);
		return err;
	}
	return -ENODEV;
}

static int drbd_proc_release(struct inode *inode, struct file *file)
{
	module_put(THIS_MODULE);
	return single_release(inode, file);
}
