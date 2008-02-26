#!/bin/bash
#
#  snapshot-resync-target-lvm.sh
#  This file is part of DRBD by Philipp Reisner and Lars Ellenberg.
#

# The caller (drbdadm) sets DRBD_RESOURCE for us.

logger -s -t drbd-snapshot "$0 invoked for $DRBD_RESOURCE"

BACKING_BDEV=$(drbdadm sh-ll-dev $DRBD_RESOURCE)
lvdisplay $BACKING_BDEV > /dev/null || exit 0 # not a LV

SNAP_PERC=10
SNAP_ADDITIONAL_S=10240
SNAP_NAME=${BACKING_BDEV##*/}-before-resync
DEFAULTFILE="/etc/default/drbd-snapshot"

if [ -f $DEFAULTFILE ]; then
	. $DEFAULTFILE
fi

if [[ $0 == *unsnapshot* ]]; then
	VG_PATH=${BACKING_BDEV%/*}
	LOG_MSG=$(lvremove -f ${VG_PATH}/${SNAP_NAME})
	logger -s -t drbd-snapshot $LOG_MSG
else
        DRBD_DEV=$(drbdadm sh-dev $DRBD_RESOURCE)
	DRBD_MINOR=${DRBD_DEV##/dev/drbd}
	_OOS=$(cat /proc/drbd | grep -A 2 ${DRBD_MINOR}: | tr ' ' '\n' | grep oos)
	OUT_OF_SYNC=${_OOS##oos:} # unit KiB
	_BDS=$(blockdev --getsize64 $BACKING_BDEV)
	BACKING_S=$((_BDS / 1024)) # unit KiB
	SNAP_SIZE=$((OUT_OF_SYNC + SNAP_ADDITIONAL_S + BACKING_S * SNAP_PERC / 100))
	LOG_MSG=$(lvcreate -s -n $SNAP_NAME -L ${SNAP_SIZE}k $BACKING_BDEV)
	logger -s -t drbd-snapshot $LOG_MSG
fi

