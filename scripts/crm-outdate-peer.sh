#!/bin/bash
#

# try to get possible output on stdout/err to syslog
PROG=${0##*/}
exec > >(2>&- ; logger -t "$PROG[$$]" -p local5.info) 2>&1
echo "invoked for $DRBD_RESOURCE"

# Default to sending email to root, unless otherwise specified
CIB_RESOURCE=${1}

# check arguments specified on command line
if [ -z "$CRM_RESOURCE" ]; then
	echo "You must specify a resource defined in the CIB when using this handler." >&2
	exit 1
fi

# check envars normally passed in by drbdadm
for var in DRBD_RESOURCE DRBD_PEER; do
	if [ -z "${!var}" ]; then
		echo "Environment variable \$$var not found (this is normally passed in by drbdadm)." >&2
		exit 1
	fi
done

: ${DRBD_CONF:="usually /etc/drbd.conf"}

DRBD_LOCAL_HOST=$(hostname)

case `basename $0` in
    *outdate-peer.sh)
	crm configure <<EOF
location drbd-outdate-${CIB_RESOURCE} ${CIB_RESOURCE} 
  rule \$id=drbd-outdate-rule-${CIB_RESOURCE} \$role="Master" -inf: \#uname eq ${DRBD_PEER}
commit
EOF
	;;
rc=$?

if [ $rc -eq 0 ]; then
    # 4: successfully outdated
    exit 4
fi
# 1: unexpected error
exit 1
