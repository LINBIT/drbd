#!/bin/bash
# vim: set foldmethod=marker nofoldenable :
# $Id: functions.sh,v 1.1.2.1 2004/05/27 12:44:18 lars Exp $
#DEBUG="-vx"
#DEBUG="-v"

[[ "__YES__" == $__I_MEAN_IT__ ]] || return 1 # don't use directly unless you know why.

#
# tests             {{{1
########################

#
# generic           {{{2
########################

# brute, but working
generic_test_stop()
{
	: ${MNT:?unknown mount point}
	grep -q " $MNT " /proc/mounts && {
		fuser -TERM -vkm $MNT/ && sleep 2 &&
		while fuser -vkm $MNT/ ; do sleep 1 ; done
	}
	sleep 1
	true
}

#
# tiobench            {{{2
########################

tiobench_start()
{
	: ${MNT:?unknown mount point}
	cd $MNT
	exec tiobench.pl --numruns 10 --threads 2 --size 100 --verify
}

#
# wbtest            {{{2
########################

wbtest_start()
{
	: ${MNT:?unknown mount point}
	WBTLOG=~/wbtest.log
	cd $MNT
	mkdir -p checkpoint
	mkdir -p data
	echo RESTART >> $WBTLOG
	date >> $WBTLOG

	wbtest -s checkpoint -t data -l $WBTLOG -V || true
	df .
# CHANGE, but be aware that -c 20, and two resources, you will have a load of ~40 :)
	wbtest -p 0 -c 5 -s checkpoint -t data -l $WBTLOG || true
}

#
# dummy            {{{2
########################

dummy_start()
{
	: ${MNT:?unknown mount point}
	cd $MNT
	while true; do touch dummy_test.$$; sleep 1; done
}

# 1}}}

#
# generic hw layer  {{{1
########################

on()
#
# execute on a remote box some of the other functions defined in this file.
# on $host_ip: function_name var1=val1 var2=val2 ...
#
{
	local host=${1%:}
	local cmd=`type $2|tail +2`
	local IFS=$'\n'
	local env="\
set -o errexit $DEBUG
PATH=/root/bin:/usr/bin:/bin:/usr/sbin:/sbin
${*:3}
"
	: ${host:?unknown host}
	: ${cmd:?no command}
	# printf "%q " ssh -2 -4 -o BatchMode=yes -o KeepAlive=yes -xl root $host -- "$env$cmd; $2"
	ssh -2 -4 -o BatchMode=yes -o KeepAlive=yes -xl root $host -- "$env$cmd; $2"
}

#
# Node              {{{2
########################

do_initial_sanity_check()
{
	: ${hostname:?unknown hostname} 
	[[ `uname -n` == $hostname ]]
	if [ -e /proc/drbd ] ; then
		for d in `grep -o "^/dev/nb[^ ]\+" /proc/mounts` ; do
			fuser -vmk $d || true
			umount $d
		done
		if tail +3 /proc/drbd | grep -q -v Unconfigured ; then
			drbdadm down all || exit 1
		fi
		if lsmod | grep -qw drbd ; then
			rmmod drbd || exit 1
		fi
	fi
	> /etc/drbd-07.conf # no more drbd-07.conf hehehe...
	[ -e /proc/drbd ] || modprobe drbd minor_count=4 || exit 1
	echo "$hostname just forgot its configuration..."
	# FIXME more paranoia
}

do_sanity_check()
{
	: ${hostname:?unknown hostname} 
	[[ `uname -n` == $hostname ]]
	# FIXME more paranoia
}

generic_heartbeat()
{
	: ${ip:?unknown admin ip} 
	set +xv
	while true ; do 
		ping -c 1 -w 2 -W 2 $ip >/dev/null ||
		ping -c 1 -w 2 -W 2 $ip >/dev/null || break
		sleep 1
	done
	return 0
}

generic_wait_for_boot()
{
	[[ -z $initial ]] && initial=false || initial=true
	: ${ip:?unknown admin ip} 
	: ${hostname:?unknown hostname} 
	while true; do
		ping -c 1 $ip > /dev/null && break
		[[ $? == 2 ]] && exit 2
		if ! (( SECONDS % 30 )) ; then
			echo "$hostname [$ip] still not responding"
		fi
		(( SECONDS > timeout )) &&
			echo "$hostname [$ip] still not responding after $SECONDS seconds, giving up." && exit 2
		sleep 1
	done
	echo "$hostname seems to be up, trying ssh connect"

	$initial || sleep 4 # give sshd time to bind
	retry=4
	while (( retry-- )) ; do
		if $initial; then
			on $ip: do_initial_sanity_check hostname=$hostname && break
		else
			on $ip: do_sanity_check         hostname=$hostname && break
		fi
		echo "admin connect failed, retrying $retry times"
		sleep 5
	done
	(( retry )) || exit 1
}

generic_do_crash()
{
	# XXX                   usleep 50000 ??
	( sleep 1; echo b > /etc/sysrq-trigger ; /sbin/reboot -nf ) </dev/null >/dev/null 2>&1 &
	exit 0
}

#
# Link              {{{2
########################

iptables_DROP()
{
	: ${nic:?unknown nic} 
	: ${hostname:?unknown hostname} 
	iptables -nvL OUTPUT | tail +3 |
		grep -q ".* DROP  *all  -- *\* *$nic *[0./ ]*$" ||
		iptables -I OUTPUT -o $nic -j DROP
	iptables -nvL INPUT | tail +3 |
		grep -q ".* DROP  *all  -- *$nic *\* *[0./ ]*$" ||
		iptables -I INPUT -i $nic -j DROP
	echo "down'ed $nic on $hostname"
}

iptables_UNDROP()
{
	: ${nic:?unknown nic} 
	: ${hostname:?unknown hostname} 
	iptables -nvL OUTPUT | tail +3 |
		grep -q ".* DROP  *all  -- *\* *$nic *[0./ ]*$" &&
		iptables -D OUTPUT -o $nic -j DROP
	iptables -nvL INPUT | tail +3 |
		grep -q ".* DROP  *all  -- *$nic *\* *[0./ ]*$" &&
		iptables -D INPUT -i $nic -j DROP
	echo "up'ed $nic on $hostname"
}

#
# Disk              {{{2
########################

dmsetup_linear()
{
	: ${name:?unknown dm name} 
	: ${dev:?unknown lower level device} 
	dmsetup ls | grep -q $name || dmsetup create $name </dev/null || exit 1
	blocks=$(fdisk -s $dev)
	dmsetup suspend $name &&
	echo "0 $[blocks*2] linear $dev 0" | dmsetup reload $name /dev/stdin || exit 1
	dmsetup resume $name
       	# dmsetup info $name
	echo -n "up'ed /dev/mapper/$name on $HOSTNAME: "
	dmsetup table $name
}

dmsetup_error()
{
	: ${name:?unknown dm name} 
	: ${dev:?unknown lower level device} 
	dmsetup ls | grep -q $name || dmsetup create $name </dev/null || exit 1
	blocks=$(fdisk -s $dev)
	dmsetup suspend $name &&
	echo "0 $[blocks*2] error" | dmsetup reload $name /dev/stdin || exit 1
	dmsetup resume $name
       	# dmsetup info $name
	echo -n "down'ed /dev/mapper/$name on $HOSTNAME: "
	dmsetup table $name
}

#
# DRBD              {{{2
########################

drbd_append_config()							# {{{3
{
	: ${RES:?unknown resource name}
	: ${LO_DEV:?unknown lo level device}
	: ${NAME:?unknown dm name}
	# : ${USIZE:?unknown device size} # TODO

	# FIXME support external meta data

	cat >> /etc/drbd-07.conf
	drbdadm dump $RES &>/dev/null

	RSIZE=$(fdisk -s $LO_DEV)
	# USIZE=${USIZE:+$[(USIZE+128)*1024]} # FIXME assert USIZE <= RSIZE
	: ${USIZE:=$RSIZE}
	let "MLOC=USIZE-128*1024"
	echo -n "Wipeout GC and AL area on $LO_DEV via /dev/mapper/$NAME for resource $RES"
	# drbdadm down $RES
	dd if=/dev/zero bs=1024 seek=$MLOC count=128 of=/dev/mapper/$NAME &>/dev/null
	sync
	echo .
	drbdadm up $RES
	# cat /proc/drbd
	echo "up'ed drbd $RES on $HOSTNAME"
}

drbdadm_up()								# {{{3
{
	: ${name:?unknown dm name} 
	drbdadm up $name
	# cat /proc/drbd
	echo "up'ed drbd $name on $HOSTNAME"
}

drbdadm_down()								# {{{3
{
	: ${name:?unknown dm name} 
	drbdadm down $name
	# cat /proc/drbd
	echo "down'ed drbd $name on $HOSTNAME"
}

drbd_wait_sync()							# {{{3
{
	: ${minor:?unknown minor number} 
	drbdsetup /dev/nb$minor wait_connect -d 0 -t 0
	drbdsetup /dev/nb$minor wait_sync -t 0
	# cat /proc/drbd
}

drbd_wait_peer_not_pri()						# {{{3
{
	: ${minor:?unknown minor number} 
	# FIXME does not work for minor > 9
	while true; do
		grep -q "^ $minor:.*/Primary" /proc/drbd || break
		sleep 1
		# FIXME currently hardcoded timeout ...
		(( SECONDS > 30 )) && exit 1
	done
	exit 0
}

drbd_reattach()								# {{{3
{
	: ${minor:?unknown minor number} 
	: ${name:?unknown resource name} 
	if drbdsetup /dev/nb$minor show | grep "^Lower device:.*null"; then
		drbdadm attach $name
	fi
}

#
# FileSystem
########################

drbdadm_pri()
{
	: ${name:?unknown resource name} 
	drbdadm primary $name
}

drbdadm_sec()
{
	: ${name:?unknown resource name} 
	drbdadm secondary $name
}

do_mount()
{
	: ${MNT:?unknown mount point} 
	: ${TYPE:?unknown fs type} 
	: ${DEV:?which device are you talkin about}
	mount -t $TYPE $DEV $MNT
}

do_umount()
{
	: ${MNT:?unknown mount point} 
	while grep -q " $MNT " /proc/mounts ; do
		umount $MNT/ && break
		fuser -vmk $MNT/ || true
		sleep 1
	done
}

mkfs_reiserfs()
{
	: ${DEV:?which device are you talkin about}
	mkreiserfs -f --format 3.6 $DEV
}

mkfs_ext2()
{
	: ${DEV:?which device are you talkin about}
	mke2fs -m0 $DEV
}

mkfs_ext3()
{
	: ${DEV:?which device are you talkin about}
	mke2fs -j -m0 $DEV
}

mkfs_xfs()
{
	: ${DEV:?which device are you talkin about}
	mkfs.xfs -f $DEV
}

# 1}}}

set -o errexit
#set -o errexit $DEBUG
