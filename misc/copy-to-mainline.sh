#! /bin/sh
# SPDX-License-Identifier: GPL-2.0-only
#
# Copy all source files from the out-of-tree DRBD repository to the
# appropriate places in an upstream Linux kernel source tree.

if [ "$#" -ne 1 ]; then
	echo "Usage: $0 <kernel source directory>"
	exit 1
fi

KDIR=$(readlink -f "$1")
if [ ! -d "$KDIR" ]; then
	echo "Kernel directory $KDIR not found"
	exit 1
fi

if [ ! -f "drbd/drbd_main.c" ]; then
	echo "Must be called from the base directory of the drbd repository"
	exit 1
fi

pushd drbd > /dev/null

cp drbd_sender.c $KDIR/drivers/block/drbd/drbd_worker.c

cp drbd_actlog.c drbd_bitmap.c drbd_dax_pmem.[ch] drbd_debugfs.[ch] \
	drbd_interval.[ch] drbd_int.h drbd_kref_debug.[ch] \
	drbd_main.c drbd_nla.[ch] drbd_nl.c \
	drbd_polymorph_printk.h drbd_proc.c drbd_receiver.c drbd_req.[ch] \
	drbd_state.[ch] drbd_state_change.h drbd_transport.c \
	drbd_transport_tcp.c drbd_transport_template.c drbd_vli.h \
	drbd-headers/drbd_transport.h drbd-headers/drbd_strings.[ch] \
	drbd-headers/drbd_protocol.h drbd-headers/drbd_meta_data.h \
	$KDIR/drivers/block/drbd/

hl=drbd-headers/linux
cp $hl/drbd_genl_api.h $hl/drbd_genl.h $hl/drbd_limits.h $hl/drbd.h \
	$hl/genl_magic_func.h $hl/genl_magic_struct.h \
	$hl/genl_magic_func-genl_register_family_with_ops_groups.h \
	$hl/genl_magic_func-genl_register_mc_group.h \
	linux/drbd_config.h \
	$KDIR/include/linux/

cp kref_debug.[ch] \
	$KDIR/include/

popd > /dev/null

git -C $KDIR --no-pager diff --stat
