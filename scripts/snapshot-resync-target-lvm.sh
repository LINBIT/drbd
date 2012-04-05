#!/bin/bash
#
#  snapshot-resync-target-lvm.sh
#  This file is part of DRBD by Philipp Reisner and Lars Ellenberg.
#
# The caller (drbdadm) sets for us:
# DRBD_RESOURCE, DRBD_VOLUME, DRBD_MINOR, DRBD_LL_DISK etc.
#
###########
#
# There will be no resync if this script terminates with an
# exit code != 0. So be carefull with the exit code!
#

export LC_ALL=C LANG=C

if [[ -z "$DRBD_RESOURCE" || -z "$DRBD_LL_DISK" ]]; then
	echo "DRBD_RESOURCE/DRBD_LL_DISK is not set. This script is supposed to"
	echo "get called by drbdadm as a handler script"
	exit 0
fi

PROG=$(basename $0)
exec > >(exec 2>&- ; logger -t "$PROG[$$]" -p local5.info) 2>&1
echo "invoked for $DRBD_RESOURCE/$DRBD_VOLUME (drbd$DRBD_MINOR)"

TEMP=$(getopt -o p:a:nv --long percent:,additional:,disconnect-on-error,verbose -- "$@")

if [ $? != 0 ]; then
	echo "getopt failed"
	exit 0
fi

if BACKING_BDEV=$(drbdadm sh-ll-dev "$DRBD_RESOURCE/$DRBD_VOLUME"); then
	is_stacked=false
elif BACKING_BDEV=$(drbdadm sh-ll-dev "$(drbdadm -S sh-lr-of "$DRBD_RESOURCE")/$DRBD_VOLUME"); then
	is_stacked=true
else
	echo "Cannot determine lower level device of resource $DRBD_RESOURCE/$DRBD_VOLUME, sorry."
	exit 0
fi

set_vg_lv_size()
{
	local X
	if ! X=$(lvs --noheadings --nosuffix --units s -o vg_name,lv_name,lv_size "$BACKING_BDEV") ; then
		# if lvs cannot tell me the info I need,
		# this is:
		echo "Cannot create snapshot of $BACKING_BDEV, apparently no LVM LV."
		return 1
	fi
	set -- $X
	VG_NAME=$1 LV_NAME=$2 LV_SIZE_K=$[$3 / 2]
	return 0
}
set_vg_lv_size || exit 0 # clean exit if not an lvm lv


SNAP_PERC=10
SNAP_ADDITIONAL=10240
DISCONNECT_ON_ERROR=0
LVC_OPTIONS=""
BE_VERBOSE=0
SNAP_NAME=$LV_NAME-before-resync
$is_stacked && SNAP_NAME=$SNAP_NAME-stacked
DEFAULTFILE="/etc/default/drbd-snapshot"

if [ -f $DEFAULTFILE ]; then
	. $DEFAULTFILE
fi

## command line parameters override default file

eval set -- "$TEMP"
while true; do
	case $1 in
	-p|--percent)
		SNAP_PERC="$2"
		shift
		;;
	-a|--additional)
		SNAP_ADDITIONAL="$2"
		shift
		;;
	-n|--disconnect-on-error)
		DISCONNECT_ON_ERROR=1
		;;
	-v|--verbose)
		BE_VERBOSE=1
		;;
	--)
		break
		;;
	esac
	shift
done
shift # the --

LVC_OPTIONS="$@"

if [[ $0 == *unsnapshot* ]]; then
	[ $BE_VERBOSE = 1 ] && set -x
	lvremove -f $VG_NAME/$SNAP_NAME
	exit 0
else
	(
		set -e
		[ $BE_VERBOSE = 1 ] && set -x
		case $DRBD_MINOR in
			*[!0-9]*|"")
			if $is_stacked; then
				DRBD_MINOR=$(drbdadm -S sh-minor "$DRBD_RESOURCE")
			else
				DRBD_MINOR=$(drbdadm sh-minor "$DRBD_RESOURCE")
			fi
			;;
		*)
			:;; # ok, already exported by drbdadm
		esac

		OUT_OF_SYNC=$(sed -ne "/^ *$DRBD_MINOR:/ "'{
				n;
				s/^.* oos:\([0-9]*\).*$/\1/;
				s/^$/0/; # default if not found
				p;
				q; }' < /proc/drbd) # unit KiB
		SNAP_SIZE=$((OUT_OF_SYNC + SNAP_ADDITIONAL + LV_SIZE_K * SNAP_PERC / 100))
		lvcreate -s -n $SNAP_NAME -L ${SNAP_SIZE}k $LVC_OPTIONS $VG_NAME/$LV_NAME
	)
	RV=$?
	[ $DISCONNECT_ON_ERROR = 0 ] && exit 0
	exit $RV
fi
