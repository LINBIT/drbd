// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2001, LINBIT HA-Solutions GmbH.
 */

#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include "drbd_int.h"
#include "drbd_transport.h"
#include "drbd_legacy_84.h"

struct proc_dir_entry *drbd_proc;

int drbd_seq_show(struct seq_file *seq, void *v)
{
	bool any_legacy;
	static const char legacy_info[] =
#ifdef CONFIG_DRBD_COMPAT_84
		" (compat 8.4)";
#else
		"";
#endif

	seq_printf(seq, "version: " REL_VERSION " (api:%d/proto:%d-%d)%s\n%s\n",
		   GENL_MAGIC_VERSION, PRO_VERSION_MIN, PRO_VERSION_MAX, legacy_info,
		   drbd_buildtag());

	any_legacy = drbd_show_legacy_device(seq, v);
	if (!any_legacy) {
		/*
		 * DRBD 8 did not output the transport information, so do not
		 * display it if any resources are in DRBD 8 compatibility mode.
		 */
		drbd_print_transports_loaded(seq);
	}
	return 0;
}
