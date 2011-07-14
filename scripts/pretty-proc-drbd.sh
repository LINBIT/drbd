#!/bin/bash
PATH=/sbin:$PATH
DEFAULTS=/etc/defaults/drbd-pretty-status

# for highlighting see console_codes(4)

colorize=false
short=true

# node role: Primary Secondary Unknown
c_pri_1=$'\e[44m'  c_pri_0=$'\e[49m'
#c_sec_1=$'\e[7m'  c_sec_0=$'\e[27m'
c_sec_1=""         c_sec_0=""
c_unk_1=$'\e[43m'  c_unk_0=$'\e[49m'

# connection state:
# Unconfigured
#
# StandAlone
c_sta_1=$'\e[34m' c_sta_0=$'\e[39m'
# Disconnecting Unconnected Timeout BrokenPipe NetworkFailure ProtocolError TearDown
c_net_bad_1=$'\e[41m' c_net_bad_0=$'\e[49m'
# WFConnection WFReportParams
c_wfc_1=$'\e[36m'      c_wfc_0=$'\e[39m'
# Connected
c_con_1=$'\e[32m'     c_con_0=$'\e[39m'
# StartingSyncS StartingSyncT WFBitMapS WFBitMapT WFSyncUUID
c_ssy_1=$'\e[35m'     c_ssy_0=$'\e[39m'
# SyncSource PausedSyncS
c_src_1=$'\e[46m'     c_src_0=$'\e[49m'
# SyncTarget PausedSyncT
c_tgt_1=$'\e[41m'     c_tgt_0=$'\e[49m'

# disk state:
# Attaching Negotiating DUnknown Consistent
# uncolored for now
#
# Diskless Failed Inconsistent
c_dsk_bad_1=$'\e[41m' c_dsk_bad_0=$'\e[49m'
# Outdated
c_out_1=$'\e[43m'     c_out_0=$'\e[44m'
# UpToDate
c_u2d_1=$'\e[32m'     c_u2d_0=$'\e[39m'

while true; do
case "$1" in
-c)	colorize=true; shift;;
-v)	short=false; shift;;
*)	break;;
esac
done

drbd_pretty_status()
{
    if ! $short ||
       ! type column &> /dev/null ||
       ! type paste &> /dev/null ||
       ! type join &> /dev/null ||
       ! type sed &> /dev/null ||
       ! type tr &> /dev/null
    then
	cat /proc/drbd
    else
	sed -e '2q' < /proc/drbd
	sed_script=$(
		i=0;
		_sh_status_process() {
			let i++ ;
			stacked=${_stacked_on:+"^^${_stacked_on_minor:-${_stacked_on//[!a-zA-Z0-9_ -]/_}}"}
			printf "s|^ *%u:|%6u\t&%s%s|\n" \
				$_minor $i \
				"${_res_name//[!a-zA-Z0-9_ -]/_}" "$stacked"
		};
		eval "$(drbdadm sh-status)" )

	p() {
		sed -e "1,2d" \
		      -e "$sed_script" \
		      -e '/^ *[0-9]\+: cs:Unconfigured/d;' \
		      -e 's/^\(.* cs:.*[^ ]\)   \([rs]...\)$/\1 - \2/g' \
		      -e 's/^\(.* \)cs:\([^ ]* \)st:\([^ ]* \)ds:\([^ ]*\)/\1\2\3\4/' \
		      -e 's/^\(.* \)cs:\([^ ]* \)ro:\([^ ]* \)ds:\([^ ]*\)/\1\2\3\4/' \
		      -e 's/^\(.* \)cs:\([^ ]*\)$/\1\2/' \
		      -e 's/^ *[0-9]\+:/ x &??not-found??/;' \
		      -e '/^$/d;/ns:.*nr:.*dw:/d;/resync:/d;/act_log:/d;' \
		      -e 's/^\(.\[.*\)\(sync.ed:\)/... ... \2/;/^.finish:/d;' \
		      -e 's/^\(.[0-9 %]*oos:\)/... ... \1/' \
		      < "/proc/drbd" | tr -s '\t ' '  ' 
	}
	m() {
		join -1 2 -2 1 -o 1.1,2.2,2.3 \
			<( ( drbdadm sh-dev all ; drbdadm -S sh-dev all ) | cat -n | sort -k2,2) \
			<(sort < /proc/mounts ) |
			sort -n | tr -s '\t ' '  ' | sed -e 's/^ *//'
	}
	# echo "=== p ==="
	# p
	# echo "=== m ==="
	# m
	# echo "========="
	# join -a1 <(p|sort) <(m|sort)
	# echo "========="
	(
	echo m:res cs ro ds p mounted fstype
	join -a1 <(p|sort) <(m|sort) | cut -d' ' -f2-6,8- | sort -k1,1n -k2,2
	) | column -t
    fi |
	if [[ $colorize != true ]]; then
		cat
	else
		c_bold=$'\e[1m' c_norm=$'\e[0m'
		sed -e "
s/^??not-found??/$c_dsk_bad_1&$c_dsk_bad_0/g;
s/^[^\t ]\+/$c_bold&$c_norm/;
s/Primary/$c_pri_1&$c_pri_0/g;
s/Secondary/$c_sec_1&$c_sec_0/g;
s/\<Unknown/$c_unk_1&$c_unk_0/;
s/StandAlone/$c_sta_1&$c_sta_0/;
s/\(Disconnecting|Unconnected|Timeout|BrokenPipe|NetworkFailure|ProtocolError|TearDown\)/$c_net_bad_1&$c_net_bad_0/;
s/\(WFConnection|WFReportParams\)/$c_wfc_1&$c_wfc_0/;
s/Connected/$c_con_1&$c_con_0/;
s/\(StartingSync.|WFBitMap.|WFSyncUUID\)/$c_ssy_1&$c_ssy_0/;
s/\(SyncSource|PausedSyncS\)/$c_src_1&$c_src_0/;
s/\(SyncTarget|PausedSyncT\)/$c_tgt_1&$c_tgt_0/;
s/\(SyncTarget|PausedSyncT\)/$c_tgt_1&$c_tgt_0/;
s/\(Diskless|Failed|Inconsistent\)/$c_dsk_bad_1&$c_dsk_bad_0/g;
s/Outdated/$c_out_1&$c_out_0/g;
s/UpToDate/$c_u2d_1&$c_u2d_0/g;
"
	fi
}

# and there you can override all highlight definitions again
test -r "$DEFAULTS" && . "$DEFAULTS"

drbd_pretty_status
