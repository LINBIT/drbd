#!/bin/bash
#
#  snapshot-resync-target-lvm.sh
#  This file is part of DRBD by Philipp Reisner and Lars Ellenberg.
#
# The caller (drbdadm) sets DRBD_RESOURCE for us.
#
###########
#
# There will be no resync if this script terminates with an
# exit code != 0. So be carefull with the exit code!
#

logger -s -t drbd-snapshot "$0 invoked for $DRBD_RESOURCE"

TEMP=$(getopt -o p:a:n --long percent:,additional:,disconnect-on-error -- "$@")

if [ $? != 0 ]; then
	logger -s -t drbd-snapshot "getopt failed"
	exit 0
fi

BACKING_BDEV=$(drbdadm sh-ll-dev $DRBD_RESOURCE)
lvdisplay $BACKING_BDEV > /dev/null || exit 0 # not a LV

SNAP_PERC=10
SNAP_ADDITIONAL=10240
DISCONNECT_ON_ERROR=0
SNAP_NAME=${BACKING_BDEV##*/}-before-resync
DEFAULTFILE="/etc/default/drbd-snapshot"

eval set -- "$TEMP"
while true; do
	case $1 in
		-p|--percent)
			SNAP_PERC="$2"
			shift
			;;
		-a|--additional)
			SNAP_ADDITIONAL="$2"
			shift 2
			;;
		-n|--disconnect-on-error)
			DISCONNECT_ON_ERROR=1
			shift
			;;
		--)
			shift
			break
			;;
	esac
done

if [ -f $DEFAULTFILE ]; then
	. $DEFAULTFILE
fi

if [[ $0 == *unsnapshot* ]]; then
	VG_PATH=${BACKING_BDEV%/*}
	LOG_MSG=$(lvremove -f ${VG_PATH}/${SNAP_NAME})
	logger -s -t drbd-snapshot $LOG_MSG
	exit 0
else
	LOG_MSG=$(
		set -e
		DRBD_DEV=$(drbdadm sh-dev $DRBD_RESOURCE)
		DRBD_MINOR=${DRBD_DEV##/dev/drbd}
		_OOS=$(cat /proc/drbd | grep -A 2 ${DRBD_MINOR}: | tr ' ' '\n' | grep oos)
		OUT_OF_SYNC=${_OOS##oos:} # unit KiB
		_BDS=$(blockdev --getsize64 $BACKING_BDEV)
		BACKING=$((_BDS / 1024)) # unit KiB
		SNAP_SIZE=$((OUT_OF_SYNC + SNAP_ADDITIONAL + BACKING * SNAP_PERC / 100))
		lvcreate -s -n $SNAP_NAME -L ${SNAP_SIZE}k $BACKING_BDEV 2>&1
	)
	RV=$?
	logger -s -t drbd-snapshot "$LOG_MSG"
	[ $DISCONNECT_ON_ERROR = 0 ] && exit 0
	exit $RV
fi
