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
		h # remember the current (tail of the) line
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

# drbd_fence_peer_exit_code is per the exit code
# convention of the DRBD "fence-peer" handler,
# obviously.
# 3: peer is already outdated or worse (e.g. inconsistent)
# 4: peer has been successfully fenced
# 5: peer not reachable, assumed to be dead
# 6: please outdate yourself, peer is known (or likely)
#    to have better data, or is even currently primary.
#    (actually, currently it is "peer is active primary now", but I'd like to
#    change that meaning slightly towards the above meaning)
# 7: peer has been STONITHed, thus assumed to be properly fenced
#    XXX IMO, this should rather be handled like 5, not 4.

# NOTE:
#    On loss of all cluster comm (cluster split-brain),
#    without STONITH configured, you always still risk data divergence.
#
# There are two timeouts:
#
# --timeout is how long we poll the DC for a definite "unreachable" node state,
# before we deduce that the peer is in fact still reachable.
# This should be longer than "dead time" or "stonith timeout",
# the time it takes the cluster manager to declare the other node dead and
# shoot it, just to be sure.
#
# --dc-timeout is how long we try to contact a DC before we give up.
# This is neccessary, because placing the constraint will fail (with some
# internal timeout) if no DC was available when we request the constraint.
# Which is likely if the DC crashed. Then the surviving DRBD Primary needs
# to wait for a new DC to be elected. Usually such election takes only
# fractions of a second, but it can take much longer (the default election
# timeout in pacemaker is ~2 minutes!).
#
# a) Small-ish (1s) timeout, medium (10..20s) dc-timeout:
#    Intended use case: fencing resource-only, no STONITH configured.
#
#    Even with STONITH properly configured, on cluster-split-brain this method
#    risks to complete transactions to user space which can be lost due to
#    STONITH later.
#
#    With dual-primary setup (cluster file system),
#    you should use method b).
#
# b) timeout >= deadtime, dc-timeout > timeout
#    Intended use case: fencing resource-and-stonith, STONITH configured.
#
#    Difference to a)
#
#       If peer is still reachable according to the cib,
#	we first poll the cib until timeout has elapsed,
#	or the peer becomes definetely unreachable.
#
#	This gives STONITH the chance to kill us.
#	With "fencing resource-and-stontith;" this protects us against
#	completing transactions to userland which might otherwise be lost.
#
#	We then place the constraint (if we are UpToDate), as explained below,
#	and return reachable/unreachable according to our last cib status poll.
#

#
#    replication link loss, current Primary calls this handler:
#	We are UpToDate, but we potentially need to wait for a DC election.
#	Once we have contacted the DC, we poll the cib until the peer is
#	confirmed unreachable, or timeout expired.
#	Then we place the constraint, and are done.
#
#	If it is complete communications loss, one will stonith the other.
#	For two-node clusters with no-quorum-policy=ignore, we will have a
#	deathmatch shoot-out, which the former DC is likely to win.
#
#	In dual-primary setups, if it is only replication link loss, both nodes
#	will call this handler, but only one will succeed to place the
#	constraint. The other will then typically need to "commit suicide".
#
#    Primary crash, promotion of former Secondary:
#	DC-election, if any, will have taken place already.
#	We are UpToDate, we place the constraint, done.
#
#    node or cluster crash, promotion of Secondary with replication link down:
#	We are "Only" Consistent.  Usually any "init-dead-time" or similar has
#	expired already, and the cib node states are already authoritative
#	without doing additional waiting.  If the peer is still reachable, we
#	place the constraint - if the peer had better data, it should have a
#	higher master score, and we should not have been asked to become
#	primary.  If the peer is not reachable, we don't do anything, and drbd
#	will refuse to be promoted. This is neccessary to avoid problems
#	With data diversion, in case this "crash" was due to a STONITH operation,
#	maybe the reboot did not fix our cluster communications!
#
#	Note that typically, if STONITH is in use, it has been done on any
#	unreachable node _before_ we are promoted, so the cib should already
#	know that the peer is dead - if it is.
#

try_place_constraint()
{
	local peer_state
	check_peer_node_reachable
	set_states_from_proc_drbd
	case $DRBD_peer in
	Secondary|Primary)
		# WTF? We are supposed to fence the peer,
		# but the replication link is just fine?
		echo WARNING "peer is $DRBD_peer, did not place the constraint!"
		rc=0
		return
		;;
	esac
	: == DEBUG == $peer_state/$DRBD_disk/$unreachable_peer_is ==
	case $peer_state/$DRBD_disk/$unreachable_peer_is in
	*//*)
		# Someone called this script, without the corresponding drbd
		# resource being configured. That's not very useful.
		echo WARNING "could not determine my disk state: did not place the constraint!"
		rc=0
		# keep drbd_fence_peer_exit_code at "generic error",
		# which will cause a "script is broken" message in case it was
		# indeed called as handler from within drbd
		;;
	reachable/Consistent/*|\
	reachable/UpToDate/*)
		cibadmin -C -o constraints -X "$new_constraint" &&
		drbd_fence_peer_exit_code=4 rc=0 &&
		echo INFO "peer is $peer_state, my disk is $DRBD_disk: placed constraint '$id_prefix-$master_id'"
		;;
	*/UpToDate/*)
		# We could differentiate between unreachable,
		# and DC-unreachable.  In the latter case, placing the
		# constraint will fail anyways, and  drbd_fence_peer_exit_code
		# will stay at "generic error".
		cibadmin -C -o constraints -X "$new_constraint" &&
		drbd_fence_peer_exit_code=5 rc=0 &&
		echo INFO "peer is not reachable, my disk is UpToDate: placed constraint '$id_prefix-$master_id'"
		;;
	unreachable/Consistent/outdated)
		# If the peer is not reachable, but we are only Consistent, we
		# may need some way to still allow promotion.
		# Easy way out: --force primary with drbdsetup.
		# But that would not place the constraint, nor outdate the
		# peer.  With this --unreachable-peer-is-outdated, we still try
		# to set the constraint.  Next promotion attempt will find the
		# "correct" constraint, consider the peer as successfully
		# fenced, and continue.
		cibadmin -C -o constraints -X "$new_constraint" &&
		drbd_fence_peer_exit_code=5 rc=0 &&
		echo WARNING "peer is unreachable, my disk is only Consistent: --unreachable-peer-is-outdated FORCED constraint '$id_prefix-$master_id'" &&
		echo WARNING "This MAY RISK DATA INTEGRITY"
		;;
	*)
		echo WARNING "peer is $peer_state, my disk is $DRBD_disk: did not place the constraint!"
		drbd_fence_peer_exit_code=5 rc=0
		# I'd like to return 6 here, otherwise pacemaker will retry
		# forever to promote, even though 6 is not strictly correct.
		;;
	esac
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

	# if I cannot query the local cib, give up
	local cib_xml
	cib_xml=$(cibadmin -Ql) || return
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
  <rule role=\"$role\" score=\"-INFINITY\" id=\"$id_prefix-rule-$master_id\">
    <expression attribute=\"$fencing_attribute\" operation=\"ne\" value=\"$fencing_value\" id=\"$id_prefix-expr-$master_id\"/>
  </rule>
</rsc_location>"
		if [[ -z $have_constraint ]] ; then
			# try to place it.

			# interessting:
			# In case this is a two-node cluster (still common with
			# drbd clusters) it does not have real quorum.
			# If it is configured to do stonith, and reboot,
			# and after reboot that stonithed node cluster comm is
			# still broken, it will shoot the still online node,
			# and try to go online with stale data.
			# Exactly what this "fence" hanler should prevent.
			# But setting contraints in a cluster partition with
			# "no-quorum-policy=ignore" will usually succeed.
			#
			# So we need to differentiate between node reachable or
			# not, and DRBD "Consistent" or "UpToDate".

			try_place_constraint
		elif [[ "$have_constraint" = "$(set +x; echo "$new_constraint" |
			sed_rsc_location_suitable_for_string_compare "$id_prefix-$master_id")" ]]; then
			echo INFO "suitable constraint already placed: '$id_prefix-$master_id'"
			drbd_fence_peer_exit_code=4
			rc=0
		else
			# if this id already exists, but looks different, we may have lost a shootout
			echo WARNING "constraint "$have_constraint" already exists"
			# anything != 0 will do;
			# 21 happend to be "The object already exists" with my cibadmin
			rc=21

			# maybe: drbd_fence_peer_exit_code=6
			# as this is not the constraint we'd like to set,
			# it is likely the inverse, so we probably can assume
			# that the peer is active primary, or at least has
			# better data than us, and wants us outdated.
		fi

		if [[ $rc != 0 ]]; then
			# at least we tried.
			# maybe it was already in place?
			echo WARNING "DATA INTEGRITY at RISK: could not place the fencing constraint!"
		fi

		# XXX policy decision:
		if $suicide_on_failure_if_primary && [[ $DRBD_role = Primary ]] &&
			[[ $drbd_fence_peer_exit_code != [3457] ]]; then
			commit_suicide # shell function yet to be written
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

# return value in $peer_state:
# reachable
#	Peer is probably still reachable.  We have had at least one successful
#	round-trip with cibadmin -Q to the DC.
# unreachable
#	Peer is not reachable, according to the cib of the DC.
# DC-unreachable
#	We have not been able to contact the DC.
check_peer_node_reachable()
{
	# We would really need a reliable method to find out if hearbeat/pacemaker
	# can reach the other node(s). Waiting for heartbeat's dead time and then
	# looking at the CIB is the only solution I currently have.

	# we are going to increase the cib timeout with every timeout.
	# for the actual invocation, we use int(cibtimeout/10).
	local cibtimeout=10
	local node_state state_lines nr_other_nodes
	while :; do
		while :; do
			# TODO It would be great to figure out that a node is definitly
			# still reachable without resorting to sleep and repoll for
			# timeout seconds.
			# Update our view of the cib, ask the DC this time.
			# Timeout, in case no DC is available.
			# Caution, some cibadmin (pacemaker 0.6 and earlier)
			# apparently use -t use milliseconds, so will timeout
			# many times until a suitably long timeout is reached
			# by increasing below.
			cib_xml=$(cibadmin -Q -t $[cibtimeout/10]) && break

			# bash magic $SECONDS is seconds since shell invocation.
			if (( $SECONDS > $dc_timeout )) ; then
				# unreachable: cannot even reach the DC
				peer_state="DC-unreachable"
				return
			fi

			# try again, longer timeout.
			let "cibtimeout = cibtimeout * 5 / 4"
		done
		state_lines=$(echo "$cib_xml" | grep '<node_state')

		if $CTS_mode; then
			# CTS requires startup-fencing=false.
			# For PartialStart, NearQuorumPoint and similar tests,
			# we would likely stay Consistent, and refuse to Promote.
			# And CTS would be very unhappy.
			# Pretend that the peer was reachable if we are missing a node_state entry for it.
			if [[ $DRBD_PEER ]] && ! echo "$state_lines" | grep -q -F uname=\"$DRBD_PEER\" ; then
				peer_state="reachable"
				echo WARNING "CTS-mode: pretending that unseen node $DRBD_PEER was reachable"
				return
			fi
		fi

		nr_other_nodes=$(echo "$state_lines" | grep -v -F uname=\"$HOSTNAME\" | wc -l)
		if [[ $nr_other_nodes -gt 1 ]]; then
			# Many nodes cluster, look at $DRBD_PEER, if set.
			# Note that this should not be neccessary.  The problem
			# we try to solve is relevant on two-node clusters
			# (no real quorum)
			if [[ $DRBD_PEER ]]; then
				if ! echo "$state_lines" | grep -v -F uname=\"$DRBD_PEER\" | grep -q 'ha="active"'; then
					peer_state="unreachable"
					return
				fi
			else
				# Loop through DRBD_PEERS. FIXME If at least
				# one of the potential peers was not "active"
				# even before this handler was called, but some
				# others are, then this may not be good enough.
				for P in $DRBD_PEERS; do
					if ! echo "$state_lines" | grep -v -F uname=\"$P\" | grep -q 'ha="active"'; then
						peer_state="unreachable"
						return
					fi
				done
			fi
		else
			# two node case, ignore $DRBD_PEERS
			if ! echo "$state_lines" | grep -v -F uname=\"$HOSTNAME\" | grep -q 'ha="active"'; then
				peer_state="unreachable"
				return
			fi
		fi

		# For a resource-and-stonith setup, or dual-primaries (which
		# you should only use with resource-and-stonith, anyways),
		# the recommended timeout is larger than the deadtime or
		# stonith timeout, and according to beekhof maybe should be
		# tuned up to the election-timeout (which, btw, defaults to 2
		# minuts!).
		if (( $SECONDS >= $timeout )) ; then
			peer_state="reachable"
			return
		fi

		# wait a bit before we poll the DC again.
		sleep 1
	done
	# NOT REACHED
}

set_states_from_proc_drbd()
{
	# DRBD_MINOR exported by drbdadm since 8.3.3
	[[ $DRBD_MINOR ]] || DRBD_MINOR=$(drbdadm ${DRBD_CONF:+ -c "$DRBD_CONF"} sh-minor $DRBD_RESOURCE) || return
	# We must not recurse into netlink,
	# this may be a callback triggered by "drbdsetup primary".
	# grep /proc/drbd instead
	set -- $(sed -ne "/^ *$DRBD_MINOR: cs:/ { s/:/ /g; p; q; }" /proc/drbd)
	DRBD_peer=${5#*/}
	DRBD_role=${5%/*}
	DRBD_disk=${7%/*}
}
############################################################

# try to get possible output on stdout/err to syslog
PROG=${0##*/}
redirect_to_logger()
{
	local lf=${1:-local5}
	case $lf in 
	# do we want to exclude some?
	auth|authpriv|cron|daemon|ftp|kern|lpr|mail|news|syslog|user|uucp|local[0-7])
		: OK ;;
	*)
		echo >&2 "invalid logfacility: $lf"
		return
		;;
	esac
	exec > >(2>&- ; logger -t "$PROG[$$]" -p $lf.info) 2>&1
}
if [[ $- != *x* ]]; then
	# you may override with --logfacility below
	redirect_to_logger local5
fi

# clean environment just in case.
unset fencing_attribute id_prefix timeout dc_timeout unreachable_peer_is
CTS_mode=false
suicide_on_failure_if_primary=false

# poor mans command line argument parsing,
# allow for command line overrides
while [[ $# != 0 ]]; do
	case $1 in
	--logfacility=*)
		redirect_to_logger ${1#*=}
		;;
	--logfacility)
		redirect_to_logger $2
		shift
		;;
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
	--role=*)
		role=${1#*=}
		;;
	-l|--role)
		role=${2}
		shift
		;;
	--fencing-attribute=*)
		fencing_attribute=${1#*=}
		;;
	-a|--fencing-attribute)
		fencing_attribute=$2
		shift
		;;
	--id-prefix=*)
		id_prefix=${1#*=}
		;;
	-p|--id-prefix)
		id_prefix=$2
		shift
		;;
	--timeout=*)
		timeout=${1#*=}
		;;
	-t|--timeout)
		timeout=$2
		shift
		;;
	--dc-timeout=*)
		dc_timeout=${1#*=}
		;;
	-d|--dc-timeout)
		dc_timeout=$2
		shift
		;;
	--CTS-mode)
		CTS_mode=true
		;;
	--unreachable-peer-is-outdated)
		# This is NOT to be scripted.
		# Or people will put this into the handler definition in
		# drbd.conf, and all this nice work was useless.
		test -t 0 &&
		unreachable_peer_is=outdated
		;;
	# --suicide-on-failure-if-primary)
	# 	suicide_on_failure_if_primary=true
	# 	;;
	-*)
		echo >&2 "ignoring unknown option $1"
		;;
	*)
		echo >&2 "ignoring unexpected argument $1"
		;;
	esac
	shift
done
# DRBD_RESOURCE: from environment
# master_id: parsed from cib

: "== unreachable_peer_is == ${unreachable_peer_is:=unknown}"
# apply defaults:
: "== fencing_attribute   == ${fencing_attribute:="#uname"}"
: "== id_prefix           == ${id_prefix:="drbd-fence-by-handler"}"
: "== role                == ${role:="Master"}"

# defaults suitable for single-primary no-stonith.
: "== timeout             == ${timeout:=1}"
: "== dc_timeout          == ${dc_timeout:=$[20+timeout]}"


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

# to be set by drbd_peer_fencing()
drbd_fence_peer_exit_code=1

case $PROG in
    crm-fence-peer.sh)
	if drbd_peer_fencing fence; then
		exit $drbd_fence_peer_exit_code
	fi
	;;
    crm-unfence-peer.sh)
	if drbd_peer_fencing unfence; then
		exit 0
	fi
esac

# 1: unexpected error
exit 1
