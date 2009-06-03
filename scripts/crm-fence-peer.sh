#!/bin/bash
#

# try to get possible output on stdout/err to syslog
PROG=${0##*/}
exec > >(2>&- ; logger -t "$PROG[$$]" -p local5.info) 2>&1

# check envars normally passed in by drbdadm
# TODO DRBD_CONF is also passed in.  we may need to use it in the
# xpath query, in case someone is crazy enough to use different
# conf files with the _same_ resource name.
# for now: do not do that, or hardcode the cib id of the master
# in the handler section of your drbd conf file.
for var in DRBD_RESOURCE; do
	if [ -z "${!var}" ]; then
		echo "Environment variable \$$var not found (this is normally passed in by drbdadm)." >&2
		exit 1
	fi
done

echo "invoked for $DRBD_RESOURCE"

# The CIB resource name, may be passed in from commandline
CIB_RESOURCE=${1}
# if not passed in, try to "guess" it from the cib
if [ -z "$CIB_RESOURCE" ]; then
	# '//master[primitive[@type="drbd" and instance_attributes/nvpair[@name = "drbd_resource" and @value="r0"]]]/@id'
	# would be what I want. But unfortunately the answer to that is empty, cibadmin cannot do that yet.
	# fall back to sed.
	CIB_RESOURCE=$(cibadmin --query --xpath \
		'//master[primitive[@type="drbd" and instance_attributes/nvpair
			[@name = "drbd_resource" and @value="r0"]]]' |
		sed -ne '1 { s/^<master id="\([^"]*\)">$/\1/p; };q')
fi

# check arguments specified on command line
if [ -z "$CIB_RESOURCE" ]; then
	echo "You must specify a resource defined in the CIB when using this handler." >&2
	exit 1
fi

DRBD_LOCAL_HOST=$(hostname)

case `basename $0` in
    crm-fence-peer.sh)
	crm configure location \
	    drbd-fence-${CIB_RESOURCE} ${CIB_RESOURCE} \
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
