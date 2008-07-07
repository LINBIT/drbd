#!/bin/bash
#
# notify.sh -- a notification handler for various DRBD events.
# This is meant to be invoked via a symlink in /usr/lib/drbd,
# by drbdadm's userspace callouts.

# try to get possible output on stdout/err to syslog
PROG=${0##*/}
exec > >(2>&- ; logger -t "$PROG[$$]" -p local5.info) 2>&1
echo "invoked for $DRBD_RESOURCE"

RECIPIENT=$1

# check arguments specified on command line
if [ -z "$RECIPIENT" ]; then
	echo "You must specify a notification recipient when using this handler." >&2
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

case "$0" in
	*split-brain.sh)
		SUBJECT="DRBD split brain on resource $DRBD_RESOURCE"
		BODY="
DRBD has detected split brain on resource $DRBD_RESOURCE
between $(hostname) and $DRBD_PEER.
Please rectify this immediately.
Please see http://www.drbd.org/users-guide/s-resolve-split-brain.html for details on doing so."
		;;
	*out-of-sync.sh)
		SUBJECT="DRBD resource $DRBD_RESOURCE has out-of-sync blocks"
		BODY="
DRBD has detected out-of-sync blocks on resource $DRBD_RESOURCE
between $(hostname) and $DRBD_PEER.
Please see the system logs for details."
		;;
	*)
		SUBJECT="Unspecified DRBD notification"
		BODY="
DRBD on $(hostname) was configured to launch a notification handler
for resource $DRBD_RESOURCE,
but no specific notification event was set.
This is most likely due to DRBD misconfiguration.
Please check your configuration file ($DRBD_CONF)."
		;;
esac

echo "$BODY" | mail -s "$SUBJECT" $RECIPIENT
