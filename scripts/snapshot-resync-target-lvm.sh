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

if [ -z "$DRBD_RESOURCE" ]; then
	echo "DRBD_RESOURCE not set. This script is supposed to"
	echo "get called by drbdadm as a handler script"
	exit 0
fi

PROG=$(basename $0)
exec > >(exec 2>&- ; logger -t "$PROG[$$]" -p local5.info) 2>&1
echo "invoked for $DRBD_RESOURCE"

TEMP=$(getopt -o p:a:nv --long percent:,additional:,disconnect-on-error,verbose -- "$@")

if [ $? != 0 ]; then
	echo "getopt failed"
	exit 0
fi

BACKING_BDEV=$(drbdadm sh-ll-dev $DRBD_RESOURCE)
lvdisplay $BACKING_BDEV > /dev/null || exit 0 # not a LV

SNAP_PERC=10
SNAP_ADDITIONAL=10240
DISCONNECT_ON_ERROR=0
LVC_OPTIONS=""
BE_VERBOSE=0
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
		-v|--verbose)
			BE_VERBOSE=1
			shift
			;;
		--)
			shift
			break
			;;
	esac
done

LVC_OPTIONS="$@"

if [ -f $DEFAULTFILE ]; then
	. $DEFAULTFILE
fi

if [[ $0 == *unsnapshot* ]]; then
	[ $BE_VERBOSE = 1 ] && set -x
	VG_PATH=${BACKING_BDEV%/*}
	lvremove -f ${VG_PATH}/${SNAP_NAME}
	exit 0
else
	(
		set -e
		[ $BE_VERBOSE = 1 ] && set -x
		DRBD_DEV=$(drbdadm sh-dev $DRBD_RESOURCE)
		DRBD_MINOR=${DRBD_DEV##/dev/drbd}
		OUT_OF_SYNC=$(sed -ne "/^ *$DRBD_MINOR:/ "'{
				n;
				s/^.* oos:\([0-9]*\).*$/\1/;
				s/^$/0/; # default if not found
				p;
				q; }' < /proc/drbd) # unit KiB
		_BDS=$(blockdev --getsize64 $BACKING_BDEV)
		BACKING=$((_BDS / 1024)) # unit KiB
		SNAP_SIZE=$((OUT_OF_SYNC + SNAP_ADDITIONAL + BACKING * SNAP_PERC / 100))
		lvcreate -s -n $SNAP_NAME -L ${SNAP_SIZE}k $LVC_OPTIONS $BACKING_BDEV
	)
	RV=$?
	[ $DISCONNECT_ON_ERROR = 0 ] && exit 0
	exit $RV
fi
