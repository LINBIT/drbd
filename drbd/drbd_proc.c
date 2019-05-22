// SPDX-License-Identifier: GPL-2.0-or-later
/*
   drbd_proc.c

   This file is part of DRBD by Philipp Reisner and Lars Ellenberg.

   Copyright (C) 2001-2008, LINBIT Information Technologies GmbH.
   Copyright (C) 1999-2008, Philipp Reisner <philipp.reisner@linbit.com>.
   Copyright (C) 2002-2008, Lars Ellenberg <lars.ellenberg@linbit.com>.


 */

#include <linux/module.h>

#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/drbd.h>
#include "drbd_int.h"
#include <drbd_transport.h>

struct proc_dir_entry *drbd_proc;

int drbd_seq_show(struct seq_file *seq, void *v)
{
	seq_printf(seq, "version: " REL_VERSION " (api:%d/proto:%d-%d)\n%s\n",
		   GENL_MAGIC_VERSION, PRO_VERSION_MIN, PRO_VERSION_MAX, drbd_buildtag());

	drbd_print_transports_loaded(seq);

	return 0;
}

