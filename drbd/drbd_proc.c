// SPDX-License-Identifier: GPL-2.0-only
/*
   drbd_proc.c

   This file is part of DRBD by Philipp Reisner and Lars Ellenberg.

   Copyright (C) 2001-2008, LINBIT Information Technologies GmbH.
   Copyright (C) 1999-2008, Philipp Reisner <philipp.reisner@linbit.com>.
   Copyright (C) 2002-2008, Lars Ellenberg <lars.ellenberg@linbit.com>.


 */

#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include "drbd_int.h"
#include "drbd_transport.h"
#include "drbd_debugfs.h"

struct proc_dir_entry *drbd_proc;

/*
 * Some resources may be operating in "DRBD 8 compatibility mode", where the
 * user created the resource using the old drbd8-style drbdsetup command line
 * syntax.
 * This implies that the user probably also expects the old drbd8-style
 * /proc/drbd output showing the device state.
 * If the flag is set for a resource, we show the old-style output for that
 * resource.
 * If any resource is in DRBD 8 compatibility mode, this function returns true.
 */
static bool show_legacy_device_info(struct seq_file *seq, void *v)
{
	bool any_legacy = false;
	int i, prev_i = -1;
	struct drbd_device *device;
	struct drbd_peer_device *peer_device;

	rcu_read_lock();
	idr_for_each_entry(&drbd_devices, device, i) {
		if (prev_i != i - 1)
			seq_putc(seq, '\n');
		prev_i = i;

		if (!device->resource->res_opts.drbd8_compat_mode)
			continue;

		any_legacy = true;
		peer_device = list_first_or_null_rcu(&device->peer_devices,
						     struct drbd_peer_device,
						     peer_devices);
		if (!peer_device)
			continue;

		drbd_seq_print_peer_device_proc_drbd(seq, peer_device);
	}
	rcu_read_unlock();
	return any_legacy;
}

int drbd_seq_show(struct seq_file *seq, void *v)
{
	bool any_legacy;
	seq_printf(seq, "version: " REL_VERSION " (api:%d/proto:%d-%d)\n%s\n",
		   GENL_MAGIC_VERSION, PRO_VERSION_MIN, PRO_VERSION_MAX,
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
