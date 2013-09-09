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

cibadmin_invocations=0
set_constraint()
{
	cibadmin_invocations=$(( $cibadmin_invocations + 1 ))
	cibadmin -C -o constraints -X "$new_constraint"
}

remove_constraint()
{
	cibadmin_invocations=$(( $cibadmin_invocations + 1 ))
	cibadmin -D -X "<rsc_location rsc=\"$master_id\" id=\"$id_prefix-$master_id\"/>"
}

cib_xml=""
get_cib_xml() {
	cibadmin_invocations=$(( $cibadmin_invocations + 1 ))
	cib_xml=$( set +x; cibadmin "$@" )
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
# There are different timeouts:
#
# --timeout is how long we poll the DC for a definite "unreachable" node state,
# before we give up and say "unknown".
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
# --network-hickup is how long we wait for the replication link to recover,
# if crmadmin confirms that the peer is in fact still alive.
# It may have been just a network hickup. If so, no need to potentially trigger
# node level fencing.
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
#	we first poll the cib/try to confirm with crmadmin,
#	until either crmadim confirms reachability, timeout has elapsed,
#	or the peer becomes definetely unreachable.
#
#	This gives STONITH the chance to kill us.
#	With "fencing resource-and-stontith;" this protects us against
#	completing transactions to userland which might otherwise be lost.
#
#	We then place the constraint (if we are UpToDate), as explained below,
#	and return reachable/unreachable according to our last cib status poll
#	or crmadmin -S result.
#

#
#    replication link loss, current Primary calls this handler:
#	We are UpToDate, but we potentially need to wait for a DC election.
#	Once we have contacted the DC, we poll the cib until the peer is
#	confirmed unreachable, or crmadmin -S confirms it as reachable,
#	or timeout expired.
#	Then we place the constraint, and are done.
#
#	If it is complete communications loss, one will stonith the other.
#	For two-node clusters with no-quorum-policy=ignore, we will have a
#	deathmatch shoot-out, which the former DC is likely to win.
#
#	In dual-primary setups, if it is only replication link loss, both nodes
#	will call this handler, but only one will succeed to place the
#	constraint. The other will then typically need to "commit suicide".
#	With stonith enabled, and --suicide-on-failure-if-primary,
#	we will trigger a node level fencing, telling
#	pacemaker to "terminate" that node,
#	and scheduling a reboot -f just in case.
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

# slightly different logic than crm_is_true
crm_is_not_false()
{
	case $1 in
	no|n|false|0|off)
		false ;;
	*)
		true ;;
	esac
}

check_cluster_properties()
{
	local x properties=$(set +x; echo "$cib_xml" |
		sed -n -e '/<crm_config/,/<\/crm_config/ !d;' \
			-e '/<cluster_property_set/,/<\/cluster_property_set/ !d;' \
			-e '/<nvpair / !d' \
			-e 's/^.* name="\([^"]*\)".* value="\([^"]*\)".*$/\1=\2/p' \
			-e 's/^.* value="\([^"]*\)".* name="\([^"]*\)".*$/\2=\1/p')

	for x in $properties ; do
		case $x in
		startup[-_]fencing=*)	startup_fencing=${x#*=} ;;
		stonith[-_]enabled=*)	stonith_enabled=${x#*=} ;;
		esac
	done

	crm_is_not_false $startup_fencing && startup_fencing=true || startup_fencing=false
	crm_is_not_false $stonith_enabled && stonith_enabled=true || stonith_enabled=false
}

try_place_constraint()
{
	local peer_state

	rc=1

	while :; do
		check_peer_node_reachable
		[[ $peer_state != "reachable" ]] && break
		# if it really is still reachable, maybe the replication link
		# recovers by itself, and we can get away without taking action?
		(( $net_hickup_time > $SECONDS )) || break
		sleep $(( net_hickup_time - SECONDS ))
	done

	set_states_from_proc_drbd
	: == DEBUG == DRBD_peer=${DRBD_peer[*]} ===
	case "${DRBD_peer[*]}" in
	*Secondary*|*Primary*)
		# WTF? We are supposed to fence the peer,
		# but the replication link is just fine?
		echo WARNING "peer is not Unknown, did not place the constraint!"
		rc=0
		return
		;;
	esac
	: == DEBUG == CTS_mode=$CTS_mode ==
	: == DEBUG == DRBD_disk_all_consistent=$DRBD_disk_all_consistent ==
	: == DEBUG == DRBD_disk_all_uptodate=$DRBD_disk_all_uptodate ==
	: == DEBUG == $peer_state/${DRBD_disk[*]}/$unreachable_peer_is ==
	if [[ ${#DRBD_disk[*]} = 0 ]]; then
		# Someone called this script, without the corresponding drbd
		# resource being configured. That's not very useful.
		echo WARNING "could not determine my disk state: did not place the constraint!"
		rc=0
		# keep drbd_fence_peer_exit_code at "generic error",
		# which will cause a "script is broken" message in case it was
		# indeed called as handler from within drbd

	# No, NOT fenced/Consistent:
	# just because we have been able to shoot him
	# does not make our data any better.
	elif [[ $peer_state = reachable ]] && $DRBD_disk_all_consistent; then
		#           = reachable ]] && $DRBD_disk_all_uptodate
		#	is implicitly handled here as well.
		set_constraint &&
		drbd_fence_peer_exit_code=4 rc=0 &&
		echo INFO "peer is $peer_state, my disk is ${DRBD_disk[*]}: placed constraint '$id_prefix-$master_id'"

	elif [[ $peer_state = fenced ]] && $DRBD_disk_all_uptodate ; then
		set_constraint &&
		drbd_fence_peer_exit_code=7 rc=0 &&
		echo INFO "peer is $peer_state, my disk is $DRBD_disk: placed constraint '$id_prefix-$master_id'"

	# Peer is neither "reachable" nor "fenced" (above would have matched)
	# So we just hit some timeout.
	# As long as we are UpToDate, place the constraint and continue.
	# If you don't like that, use a ridiculously high timeout,
	# or patch this script.
	elif $DRBD_disk_all_uptodate ; then
		# We could differentiate between unreachable,
		# and DC-unreachable.  In the latter case, placing the
		# constraint will fail anyways, and  drbd_fence_peer_exit_code
		# will stay at "generic error".
		set_constraint &&
		drbd_fence_peer_exit_code=5 rc=0 &&
		echo INFO "peer is not reachable, my disk is UpToDate: placed constraint '$id_prefix-$master_id'"

	# This block is reachable by operator intervention only
	# (unless you are hacking this script and know what you are doing)
	elif [[ $peer_state != reachable ]] && [[ $unreachable_peer_is = outdated ]] && $DRBD_disk_all_consistent; then
		# If the peer is not reachable, but we are only Consistent, we
		# may need some way to still allow promotion.
		# Easy way out: --force primary with drbdsetup.
		# But that would not place the constraint, nor outdate the
		# peer.  With this --unreachable-peer-is-outdated, we still try
		# to set the constraint.  Next promotion attempt will find the
		# "correct" constraint, consider the peer as successfully
		# fenced, and continue.
		set_constraint &&
		drbd_fence_peer_exit_code=5 rc=0 &&
		echo WARNING "peer is unreachable, my disk is only Consistent: --unreachable-peer-is-outdated FORCED constraint '$id_prefix-$master_id'" &&
		echo WARNING "This MAY RISK DATA INTEGRITY"

	# So I'm not UpToDate, and peer is not reachable.
	# Tell the module about "not reachable", and don't do anything else.
	else
		echo WARNING "peer is $peer_state, my disk is ${DRBD_disk[*]}: did not place the constraint!"
		drbd_fence_peer_exit_code=5 rc=0
		# I'd like to return 6 here, otherwise pacemaker will retry
		# forever to promote, even though 6 is not strictly correct.
	fi
	return $rc
}

commit_suicide()
{
	local reboot_timeout=20
	local extra_msg

	if $stonith_enabled ; then
		# avoid double fence, tell pacemaker to kill me
		echo WARNING "trying to have pacemaker kill me now!"
		crm_attribute -t status -N $HOSTNAME -n terminate -v 1
		echo WARNING "told pacemaker to kill me, but scheduling reboot -f in 300 seconds just in case"

		# -------------------------
		echo WARNING $'\n'"    told pacemaker to kill me,"\
			     $'\n'"    but scheduling reboot -f in 300 seconds just in case."\
			     $'\n'"    kill $$ # to cancel" | wall
		# -------------------------

		reboot_timeout=300
		extra_msg="Pacemaker terminate pending. If that fails, I'm "

	else
		# -------------------------
		echo WARNING $'\n'"    going to reboot -f in $reboot_timeout seconds"\
			     $'\n'"    kill $$ # to cancel!" | wall
		# -------------------------
	fi

	reboot_timeout=$(( reboot_timeout + SECONDS ))
	# pacemaker apparently cannot kill me.
	while (( $SECONDS < $reboot_timeout )); do
		echo WARNING "${extra_msg}going to reboot -f in $(( reboot_timeout - SECONDS )) seconds! To cancel: kill $$"
		sleep 2
	done
	echo WARNING "going to reboot -f now!"
	reboot -f
	sleep 864000
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
	get_cib_xml -Ql || return
	fence_peer_init || return

	case $1 in
	fence)

		local startup_fencing stonith_enabled
		check_cluster_properties

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

			try_place_constraint && return

			# maybe callback and operator raced for the same constraint?
			# before we potentially trigger node level fencing
			# or keep IO frozen, double check.
			# try_place_constraint has updated cib_xml from DC

			have_constraint=$(set +x; echo "$cib_xml" |
				sed_rsc_location_suitable_for_string_compare "$id_prefix-$master_id")
		fi

		if [[ "$have_constraint" = "$(set +x; echo "$new_constraint" |
			sed_rsc_location_suitable_for_string_compare "$id_prefix-$master_id")" ]]; then
			echo INFO "suitable constraint already placed: '$id_prefix-$master_id'"
			drbd_fence_peer_exit_code=4
			rc=0
		elif [[ -n "$have_constraint" ]] ; then
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
		if $suicide_on_failure_if_primary && [[ $drbd_fence_peer_exit_code != [3457] ]]; then
			set_states_from_proc_drbd
			[[ "${DRBD_role[*]}" = *Primary* ]] && commit_suicide
		fi

		return $rc
		;;
	unfence)
		if [[ -n $have_constraint ]]; then
			# remove it based on that id
			remove_constraint
		else
			return 0
		fi
	esac
}

guess_if_pacemaker_will_fence()
{
	# try to guess whether it is useful to wait and poll again,
	# (node fencing in progress...),
	# or if pacemaker thinks the node is "clean" dead.
	local x

	# "return values:"
	crmd= in_ccm= expected= join= will_fence=false

	# Older pacemaker has an "ha" attribute, too.
	# For stonith-enabled=false, the "crmd" attribute may stay "online",
	# but once ha="dead", we can stop waiting for changes.
	ha_dead=false

	for x in ${node_state%/>} ; do
		case $x in
		in_ccm=\"*\")	x=${x#*=\"}; x=${x%\"}; in_ccm=$x ;;
		crmd=\"*\")	x=${x#*=\"}; x=${x%\"}; crmd=$x ;;
		expected=\"*\")	x=${x#*=\"}; x=${x%\"}; expected=$x ;;
		join=\"*\")	x=${x#*=\"}; x=${x%\"}; join=$x ;;
		ha=\"dead\")	ha_dead=true ;;
		esac
	done

	# if it is not enabled, no point in waiting for it.
	if ! $stonith_enabled ; then
		# "normalize" the rest of the logic
		# where this is called.
		# for stonith-enabled=false, and ha="dead",
		# reset crmd="offline".
		# Then we stop polling the cib for changes.

		$ha_dead && crmd="offline"
		return
	fi

	if [[ -z $node_state ]] ; then
		# if we don't know nothing about the peer,
		# and startup_fencing is explicitly disabled,
		# no fencing will take place.
		$startup_fencing || return
	fi

	# for further inspiration, see pacemaker:lib/pengine/unpack.c, determine_online_status_fencing()
	[[ -z $in_ccm ]] && will_fence=true
	[[ $crmd = "banned" ]] && will_fence=true
	if [[ ${expected-down} = "down" && $in_ccm = "false"  && $crmd != "online" ]]; then
		: "pacemaker considers this as clean down"
	elif [[ $in_ccm = false ]] || [[ $crmd != "online" ]]; then
		will_fence=true
	fi
}

# return value in $peer_state:
# DC-unreachable
#	We have not been able to contact the DC.
# fenced
#	According to the node_state recorded in the cib,
#	the peer is offline and expected down
#	(which means successfully fenced, if stonith is enabled)
# reachable
#	cib says it's online, and crmadmin -S says peer state is "ok"
# unreachable
#	cib says it's offline (but does not yet say "expected" down)
#	and we reached the timeout
# unknown
#	cib does not say it was offline (or we don't know who the peer is)
#	and we reached the timeout
#
check_peer_node_reachable()
{
	# we are going to increase the cib timeout with every timeout (see below).
	# for the actual invocation, we use int(cibtimeout/10).
	# scaled by 5 / 4 with each iteration,
	# this results in a timeout sequence of 1 2 2 3 4 5 6 7 9 ... seconds 
	local cibtimeout=18
	local full_timeout
	local nr_other_nodes
	local other_node_uname_attrs

	# we have a cibadmin -Ql in cib_xml already
	# filter out <node uname, but ignore type="ping" nodes,
	# they don't run resources
	other_node_uname_attrs=$(set +x; echo "$cib_xml" |
		sed -e '/<node /!d; / type="ping"/d;s/^.* \(uname="[^"]*"\).*>$/\1/' |
		grep -v -F uname=\"$HOSTNAME\")
	set -- $other_node_uname_attrs
	nr_other_nodes=$#

	while :; do
		local state_lines= node_state=
		local crmd= in_ccm= expected= join= will_fence= ha_dead=

		while :; do
			local t=$SECONDS
			#
			# Update our view of the cib, ask the DC this time.
			# Timeout, in case no DC is available.
			# Caution, some cibadmin (pacemaker 0.6 and earlier)
			# apparently use -t use milliseconds, so will timeout
			# many times until a suitably long timeout is reached
			# by increasing below.
			#
			# Why not use the default timeout?
			# Because that would unecessarily wait for 30 seconds
			# or longer, even if the DC is re-elected right now,
			# and available within the next second.
			#
			get_cib_xml -Q -t $(( cibtimeout/10 )) && break

			# bash magic $SECONDS is seconds since shell invocation.
			if (( $SECONDS > $dc_timeout )) ; then
				# unreachable: cannot even reach the DC
				peer_state="DC-unreachable"
				return
			fi

			# avoid busy loop
			[[ $t = $SECONDS ]] && sleep 1

			# try again, longer timeout.
			let "cibtimeout = cibtimeout * 5 / 4"
		done
		state_lines=$( set +x; echo "$cib_xml" | grep '<node_state ' |
			grep -F -e "$other_node_uname_attrs" )

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

		# very unlikely: no DRBD_PEER passed in,
		# but in fact only one other cluster node.
		# Use that one as DRBD_PEER.
		if [[ -z $DRBD_PEER ]] && [[ $nr_other_nodes = 1 ]]; then
			DRBD_PEER=${other_node_uname_attrs#uname=\"}
			DRBD_PEER=${DRBD_PEER%\"}
		fi

		if [[ -z $DRBD_PEER ]]; then
			# Multi node cluster, but unknown DRBD Peer.
			# This should not be a problem, unless you have
			# no_quorum_policy=ignore in an N > 2 cluster.
			# (yes, I've seen such beasts in the wild!)
			# As we don't know the peer,
			# we could only safely return here if *all*
			# potential peers are confirmed down.
			# Don't try to be smart, just wait for the full
			# timeout, which should allow STONITH to
			# complete.
			full_timeout=$(( $timeout - $SECONDS ))
			if (( $full_timeout > 0 )) ; then
				echo WARNING "don't know who my peer is; sleep $full_timeout seconds just in case"
				sleep $full_timeout
			fi

			# In the unlikely case that we don't know our DRBD peer,
			#	there is no point in polling the cib again,
			#	that won't teach us who our DRBD peer is.
			#
			#	We waited $full_timeout seconds already,
			#	to allow for node level fencing to shoot us.
			#
			#	So if we are still alive, then obviously no-one has shot us.
			#

			peer_state="unknown"
			return
		fi

		#
		# we know the peer or/and are a two node cluster
		#

		node_state=$(set +x; echo "$state_lines" | grep -F uname=\"$DRBD_PEER\")

		# populates in_ccm, crmd, exxpected, join, will_fence=[false|true]
		guess_if_pacemaker_will_fence

		if ! $will_fence && [[ $crmd != "online" ]] ; then

			# "legacy" cman + pacemaker clusters older than 1.1.10
			# may "forget" about startup fencing.
			# We can detect this because the "expected" attribute is missing.
			# Does not make much difference for our logic, though.
			[[ $expected/$in_ccm = "down/false" ]] && peer_state="fenced" || peer_state="unreachable"

			return
		fi

		# So the cib does still indicate the peer was reachable.
		#
		# try crmadmin; if we can sucessfully query the state of the remote crmd,
		# it is obviously reachable.
		#
		# Do this only after we have been able to reach a DC above.
		# Note: crmadmin timeout is in milli-seconds, and defaults to 30000 (30 seconds).
		# Our variable $cibtimeout should be in deci-seconds (see above)
		# (unless you use a very old version of pacemaker, so don't do that).
		# Convert deci-seconds to milli-seconds, and double it.
		if [[ $crmd = "online" ]] ; then
			local out
			if out=$( crmadmin -t $(( cibtimeout * 200 )) -S $DRBD_PEER ) \
			&& [[ $out = *"(ok)" ]]; then
				peer_state="reachable"
				return
			fi
		fi

		# We know our DRBD peer.
		# We are still not sure about its status, though.
		#
		# It is not (yet) "expected down" per the cib, but it is not
		# reliably reachable via crmadmin -S either.
		#
		# If we already polled for longer than timeout, give up.
		#
		# For a resource-and-stonith setup, or dual-primaries (which
		# you should only use with resource-and-stonith, anyways),
		# the recommended timeout is larger than the deadtime or
		# stonith timeout, and according to beekhof maybe should be
		# tuned up to the election-timeout (which, btw, defaults to 2
		# minutes!).
		#
		if (( $SECONDS >= $timeout )) ; then
			[[ $crmd = offline ]] && peer_state="unreachable" || peer_state="unknown"
			return
		fi

		# wait a bit before we poll the DC again
		sleep 2
	done
	# NOT REACHED
}

set_states_from_proc_drbd()
{
	local IFS line lines i disk
	# DRBD_MINOR exported by drbdadm since 8.3.3
	[[ $DRBD_MINOR ]] || DRBD_MINOR=$(drbdadm ${DRBD_CONF:+ -c "$DRBD_CONF"} sh-minor $DRBD_RESOURCE) || return

	# if we have more than one minor, do a word split, ...
	set -- $DRBD_MINOR
	# ... and convert into regex:
	IFS="|$IFS"; DRBD_MINOR="($*)"; IFS=${IFS#?}

	# We must not recurse into netlink,
	# this may be a callback triggered by "drbdsetup primary".
	# grep /proc/drbd instead
	# This magic does not work, if 
	#

	DRBD_peer=()
	DRBD_role=()
	DRBD_disk=()
	DRBD_disk_all_uptodate=true
	DRBD_disk_all_consistent=true

	IFS=$'\n'
	lines=($(sed -nre "/^ *$DRBD_MINOR: cs:/ { s/:/ /g; p; }" /proc/drbd))
	IFS=$' \t\n'

	i=0
	for line in "${lines[@]}"; do
		set -- $line
		DRBD_peer[i]=${5#*/}
		DRBD_role[i]=${5%/*}
		disk=${7%/*}
		DRBD_disk[i]=${disk:-Unconfigured}
		case $disk in
		UpToDate) ;;
		Consistent)
			DRBD_disk_all_uptodate=false ;;
		*)
			DRBD_disk_all_uptodate=false
			DRBD_disk_all_consistent=false ;;
		esac
		let i++
	done
	if (( i = 0 )) ; then
		DRBD_disk_all_uptodate=false
		DRBD_disk_all_consistent=false
	fi
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
	--net-hickup=*|--network-hickup=*)
		net_hickup_time=${1#*=}
		;;
	--net-hickup|--network-hickup)
		net_hickup_time=$2
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
	--suicide-on-failure-if-primary)
		suicide_on_failure_if_primary=true
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
# DRBD_RESOURCE: from environment
# master_id: parsed from cib

: "== unreachable_peer_is == ${unreachable_peer_is:=unknown}"
# apply defaults:
: "== fencing_attribute   == ${fencing_attribute:="#uname"}"
: "== id_prefix           == ${id_prefix:="drbd-fence-by-handler"}"
: "== role                == ${role:="Master"}"

# defaults suitable for most cases
: "== net_hickup_time     == ${net_hickup_time:=0}"
: "== timeout             == ${timeout:=90}"
: "== dc_timeout          == ${dc_timeout:=20}"

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

# Fixup id-prefix to include the resource name
# There may be multiple drbd instances part of the same M/S Group, pointing to
# the same master-id. Still they need to all have their own constraint, to be
# able to unfence independently when they finish their resync independently.
# Be nice to people who already explicitly configure an id prefix containing
# the resource name.
if [[ $id_prefix != *"-$DRBD_RESOURCE" ]] ; then
	id_prefix="$id_prefix-$DRBD_RESOURCE"
	: "== id_prefix           == ${id_prefix}"
fi

# make sure it contains what we expect
HOSTNAME=$(uname -n)

echo "invoked for $DRBD_RESOURCE${master_id:+" (master-id: $master_id)"}"

# to be set by drbd_peer_fencing()
drbd_fence_peer_exit_code=1

case $PROG in
    crm-fence-peer.sh)
	if drbd_peer_fencing fence; then
		: == DEBUG == $cibadmin_invocations cibadmin calls ==
		: == DEBUG == $SECONDS seconds ==
		exit $drbd_fence_peer_exit_code
	fi
	;;
    crm-unfence-peer.sh)
	if drbd_peer_fencing unfence; then
		: == DEBUG == $cibadmin_invocations cibadmin calls ==
		: == DEBUG == $SECONDS seconds ==
		exit 0
	fi
esac

# 1: unexpected error
exit 1
