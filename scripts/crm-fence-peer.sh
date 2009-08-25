#!/bin/bash
#

sed_rsc_location_suitable_for_string_compare()
{
	# expected input: exactly one tag per line: "^[[:space:]]*<.*/?>$"
	sed -ne '
	# within the rsc_location constraint with that id,
	/<rsc_location .*\bid="'"$1"'"/, /<\/rsc_location>/ {
		/<\/rsc_location>/q # done, if closing tag is found
		s/^[[:space:]]*//   # trim spaces
		s/ *\bid="[^"]*"//  # remove id tag
		# print each attribute on its own line, by
		: attr
		h # rememver the current rest line
		# remove all but the first attribute, and print,
		s/^\([^[:space:]]*[[:space:]][^= ]*="[^"]*"\).*$/\1/p
		g # then restore the remembered line,
		# and remove the first attribute.
		s/^\([^[:space:]]*\)[[:space:]][^= ]*="[^"]*"\(.*\)$/\1\2/
		# then repeat, until no more attributes are left
		t attr
	}' | sort
}

# if not passed in, try to "guess" it from the cib
# we only know the DRBD_RESOURCE.
fence_peer_init()
{
	# we know which instance we are: $OCF_RESOURCE_INSTANCE.
	# but we do not know the xml ID of the <master/> :(
	# cibadmin -Ql --xpath \
	# '//master[primitive[@type="drbd" and instance_attributes/nvpair[@name = "drbd_resource" and @value="r0"]]]/@id'
	# but I'd have to pipe that through sed anyways, because @attribute
	# xpath queries are not supported.
	# and I'd be incompatible with older cibadmin not supporting --xpath.
	# be cool, sed it out:
	local cib_xml=$(cibadmin -Ql)
	: ${master_id=$(set +x; echo "$cib_xml" |
		sed -ne '/<master /,/<\/master>/ {
			   /<master / h;
			     /<primitive/,/<\/primitive/ {
			       /<instance_attributes/,/<\/instance_attributes/ {
				 /<nvpair .*\bname="drbd_resource"/ {
				   /.*\bvalue="'"$DRBD_RESOURCE"'"/! d
				   x
				   s/^.*\bid="\([^"]*\)".*/\1/p
				   q
				 };};};}')}
	if [[ -z $master_id ]] ; then
		echo WARNING "drbd-fencing could not determine the master id of drbd resource $DRBD_RESOURCE"
		return 1;
	fi
	have_constraint=$(set +x; echo "$cib_xml" |
		sed_rsc_location_suitable_for_string_compare "$id_prefix-$master_id")
	return 0
}

# drbd_peer_fencing fence|unfence
drbd_peer_fencing()
{
	local rc
	# input to fence_peer_init:
	# $DRBD_RESOURCE is set by command line of from environment.
	# $id_prefix is set by command line or default.
	# $master_id is set by command line or will be parsed from the cib.
	# output of fence_peer_init:
	local have_constraint new_constraint

	fence_peer_init || return

	case $1 in
	fence)
		if [[ $fencing_attribute = "#uname" ]]; then
			fencing_value=$HOSTNAME
		elif ! fencing_value=$(crm_attribute -Q -t nodes -n $fencing_attribute 2>/dev/null); then
			fencing_attribute="#uname"
			fencing_value=$HOSTNAME
		fi
		# double negation: do not run but with my data.
		new_constraint="\
<rsc_location rsc=\"$master_id\" id=\"$id_prefix-$master_id\">
  <rule role=\"Master\" score=\"-INFINITY\" id=\"$id_prefix-rule-$master_id\">
    <expression attribute=\"$fencing_attribute\" operation=\"ne\" value=\"$fencing_value\" id=\"$id_prefix-expr-$master_id\"/>
  </rule>
</rsc_location>"
		if [[ -z $have_constraint ]] ; then
			# try to place it.
			cibadmin -C -o constraints -X "$new_constraint"
			rc=$?
		elif [[ "$have_constraint" = "$(set +x; echo "$new_constraint" |
			sed_rsc_location_suitable_for_string_compare "$id_prefix-$master_id")" ]]; then
			: "identical constraint already placed"
			rc=0
		else
			# if this id already exits, but looks different, we may have lost a shootout
			echo WARNING "constraint "$have_constraint" already exists"
			# anything != 0 will do;
			# 21 happend to be "The object already exists" with my cibadmin
			rc=21
		fi

		if [ $rc != 0 ]; then
			# at least we tried.
			# maybe it was already in place?
			echo WARNING "could not place the constraint!"
		fi
		return $rc
		;;
	unfence)
		if [[ -n $have_constraint ]]; then
			# remove it based on that id
			cibadmin -D -X "<rsc_location rsc=\"$master_id\" id=\"$id_prefix-$master_id\"/>"
		else
			return 0
		fi
	esac
}

peer_node_reachable()
{
	# We would really need a reliable method to find out if hearbeat/pacemaker
	# can reach the other node(s). Waiting for heartbeat's dead time and then
	# looking at the CIB is the only sulution I currently have.
	sleep $dead_time

	local state_lines=$(cibadmin -Ql | grep '<node_state')
	local nr_other_nodes=$(echo "$state_lines" | grep -v uname=\"$(uname -n)\" | wc -l)

	if [[ $nr_other_nodes -gt 1 ]]; then
		# Many nodes cluster, look at $DRBD_PEERS
		local rc=0
		for P in $DRBD_PEERS; do
			echo "$state_lines" | grep uname=\"$P\" | grep -q 'ha="active"' || rc=1
		done
		return $rc
	fi

	# two node case, ignore $DRBD_PEERS
	echo "$state_lines" | grep -v uname=\"$(uname -n)\" | grep -q 'ha="active"'
	# return $?
}

disk_is_up_to_date()
{
	drbdsetup $(drbdadm sh-dev $DRBD_RESOURCE) dstate | grep -q "UpToDate/"
	# return $?
}
############################################################

# try to get possible output on stdout/err to syslog
PROG=${0##*/}
if [[ $- != *x* ]]; then
	exec > >(2>&- ; logger -t "$PROG[$$]" -p local5.info) 2>&1
fi

# poor mans command line argument parsing
while [[ $# != 0 ]]; do
	case $1 in
	--resource=*)
		DRBD_RESOURCE=${1#*=}
		;;
	-r|--resource)
		DRBD_RESOURCE=$2
		shift
		;;
	--master-id=*)
		master_id=${1#*=}
		;;
	-i|--master-id)
		master_id=$2
		shift
		;;
	--fencing-attribute=*)
		fencing_attribute=${1#*=}
		;;
	-a|--fencing-attribute)
		fencing_attribute=${2}
		shift
		;;
	--id-prefix=*)
		id_prefix=${1#*=}
		;;
	-p|--id-prefix)
		id_prefix=${2}
		shift
		;;
	--dead-time=*)
		dead_time=${1#*=}
		;;
	-t|--dead-time)
		dead_time=${2}
		shift
		;;
	-*)
		echo >&2 "ignoring unknown option $1"
		;;
	*)
		echo >&2 "ignoring unexpected argument $1"
		;;
	esac
	shift
done
# defaults: 
# DRBD_RESOURCE: from environment
# master_id: parsed from cib
: ${fencing_attribute:="#uname"}
: ${id_prefix:="drbd-fence-by-handler"}
: ${dead_time:=8}

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

# make sure it contains what we expect
HOSTNAME=$(uname -n)

echo "invoked for $DRBD_RESOURCE${master_id:+" (master-id: $master_id)"}"

case $PROG in
    crm-fence-peer.sh)
	if peer_node_reachable; then
		if drbd_peer_fencing fence; then
			# 4: successfully outdated (per the exit code convention
			# of the DRBD "fence-peer" handler)
			exit 4
		fi
	else
		if disk_is_up_to_date; then
			drbd_peer_fencing fence
		fi
	fi
	# We have assume that the constraint did not make it to the CIB of the peer.
	# 5: Peer not reachable (per the exit code convention
	# of the DRBD "fence-peer" handler)
	exit 5
	;;
    crm-unfence-peer.sh)
	if drbd_peer_fencing unfence; then
		exit 0
	fi
esac

# 1: unexpected error
exit 1
