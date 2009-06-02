#!/bin/bash
#

# try to get possible output on stdout/err to syslog
PROG=${0##*/}
exec > >(2>&- ; logger -t "$PROG[$$]" -p local5.info) 2>&1
echo "invoked for $DRBD_RESOURCE"

# The CIB resource name. Must be passed in.
CIB_RESOURCE=${1}

# check arguments specified on command line
if [ -z "$CIB_RESOURCE" ]; then
	echo "You must specify a resource defined in the CIB when using this handler." >&2
	exit 1
fi

# check envars normally passed in by drbdadm
for var in DRBD_RESOURCE; do
	if [ -z "${!var}" ]; then
		echo "Environment variable \$$var not found (this is normally passed in by drbdadm)." >&2
		exit 1
	fi
done

: ${DRBD_CONF:="usually /etc/drbd.conf"}

DRBD_LOCAL_HOST=$(hostname)

case `basename $0` in
    crm-fence-peer.sh)
	crm configure location \
	    drbd-fence-${CIB_RESOURCE}${CIB_RESOURCE} \
	    rule \$id=drbd-fence-rule-${CIB_RESOURCE} \
	    \$role="Master" -inf: \#uname ne ${DRBD_LOCAL_HOST}
	rc=$?
	if [ $rc -eq 0 ]; then
            # 4: successfully outdated (per the exit code convention
	    # of the DRBD "fence-peer" handler.
	    exit 4
	fi
	;;
    crm-unfence-peer.sh)
	crm configure delete drbd-fence-${CIB_RESOURCE}
	rc=$?
	if [ $rc -eq 0 ]; then
	    exit 0
	fi
	;;
esac

# 1: unexpected error
exit 1
