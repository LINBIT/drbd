#!/bin/bash
# vim: set foldmethod=marker nofoldenable :
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
		echo "killall users of $HOSTNAME:$MNT/"
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

wbtest_old_start()
{
	: ${MNT:?unknown mount point}
	WBTLOG=~/wbtest.log
	cd $MNT
	mkdir -p checkpoint
	mkdir -p data
	echo RESTART >> $WBTLOG
	date >> $WBTLOG

	wbtest -s checkpoint -t data -l $WBTLOG -V 2>&1 |
		sed '/Processed checkfile .*: \([0-9]*\)\/\1 passed/d'
	echo "remaining garbage files:"
	echo "FIXME! should be empty, but is not. wbtest does not like to be killed."
	ls -l checkpoint/ data/
	du -s checkpoint/ data/
# CHANGE, but be aware that -c 20,
# and two resources, you will have a load of ~40 :)
	wbtest -p 0 -c 5 -m 16384 -M 102400 -s checkpoint -t data -l $WBTLOG
}

wbtest_start()
{
	: ${MNT:?unknown mount point}
	WBTLOG=~/wbtest.log
	cd $MNT
	mkdir -p data
	echo RESTART >> $WBTLOG
	date >> $WBTLOG

	wbtest -d data -l $WBTLOG -V
# CHANGE, but be aware that -c 20,
# and two resources, you will have a load of ~40 :)
	wbtest -v -p 0 -c 5 -m 16384 -M 102400 -d data -l $WBTLOG > /dev/null
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
	local env="\
set -o errexit $DEBUG
PATH=/root/bin:/usr/bin:/bin:/usr/sbin:/sbin
$(printf '%q\n' "${@:3}")
"
	local err
	: ${host:?unknown host}
	: ${cmd:?no command}
	# printf "%s " ssh -2 -4 -o BatchMode=yes -o KeepAlive=yes -xl root $host -- "$env$cmd; $2"
	ssh -2 -4 -o BatchMode=yes -o KeepAlive=yes -xl root $host -- "$env$cmd; $2"
	err=$?
	[[ $err == 0 ]] || echo "$2: $err"
	return $err
}

to_syslog()
{
	logger "$MSG"
}

#
# Node              {{{2
########################

do_initial_sanity_check()
{
	: ${hostname:?unknown hostname} 
	: ${DRBD_MAJOR:?missing DRBD_MAJOR}
	: ${DRBD_DEVNAME:?missing DRBD_DEVNAME}
	: ${MINOR_COUNT:?missing MINOR_COUNT}
	test `uname -n` = $hostname
	if [ -e /proc/drbd ] ; then
		for d in `grep -o "^/dev/$DRBD_DEVNAME[^ ]\+" /proc/mounts` ; do
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
	ls_line=$(LANG= ls -l /dev/${DRBD_DEVNAME}0)
	egrep_pat="^brw-..---- +1 root +[a-z]+ +$DRBD_MAJOR, +0 [A-Za-z0-9-: ]*/dev/${DRBD_DEVNAME}0\$"
	if ! echo $ls_line | grep -E "$egrep_pat" ; then
		echo "unexpected drbd device settings"
		echo " $ls_line"
		echo "    does not match"
		echo "$egrep_pat"
		exit 1
	fi
	# [ -e /proc/drbd ] || modprobe drbd minor_count=$MINOR_COUNT major_nr=$DRBD_MAJOR || exit 1
	[ -e /proc/drbd ] || modprobe drbd minor_count=$MINOR_COUNT || exit 1
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
	: ${ip:?unknown admin ip} 
	: ${hostname:?unknown hostname} 
	# You can override these in your config
	: ${DRBD_MAJOR:=147}
	: ${DRBD_DEVNAME:=drbd}
	: ${MINOR_COUNT:=4}


	: ${initial:=false} ${have_drbd:=true}
	[[ $initial   == true ]] || [[ $initial   == false ]] || return 1
	[[ $have_drbd == true ]] || [[ $have_drbd == false ]] || return 1

	SECONDS=0   # reset bash magic variable
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
			if $have_drbd ; then
				on $ip: do_initial_sanity_check \
					hostname=$hostname \
					DRBD_DEVNAME=$DRBD_DEVNAME \
					DRBD_MAJOR=$DRBD_MAJOR \
					MINOR_COUNT=$MINOR_COUNT && break
			else
				# fixme sanity check *no drbd*
				on $ip: do_sanity_check \
					hostname=$hostname && break
			fi
		else
			on $ip: do_sanity_check hostname=$hostname && break
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
	: ${blocks:=$(fdisk -s $dev)}
	dmsetup ls | grep -q $name || dmsetup create $name </dev/null || exit 1
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
	: ${blocks:=$(fdisk -s $dev)}
	dmsetup ls | grep -q $name || dmsetup create $name </dev/null || exit 1
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

	: START_CLEAN=${START_CLEAN:+true}
	: ${START_CLEAN:=false}
	# : ${USIZE:?unknown device size} # TODO

	# FIXME support external meta data

	cat >> /etc/drbd-07.conf
	drbdadm dump $RES &>/dev/null

	RSIZE=$(fdisk -s /dev/mapper/$NAME)
	USIZE=${USIZE:+$[USIZE+128*1024]}
	: ${USIZE:=$RSIZE}
	(( USIZE <= RSIZE )) || return 1 # assert USIZE <= RSIZE
	let "MLOC=(USIZE & ~3) -128*1024"
	if $START_CLEAN ; then
		perl -e 'print pack "N8", 0,0, 1,1,1,1,1, 0x8374026a;
			 print "\x00" x (4096 - 32);
			 # and, just to see how the bitmap behaves:
			 print "\xff" x (4096 * 19);
			' | dd bs=4k seek=$[MLOC/4] of=/dev/mapper/$NAME
	else
		echo "Wipeout GC and AL area on $HOSTNAME:$LO_DEV via /dev/mapper/$NAME for resource $RES"
		# drbdadm down $RES
		# dd if=/dev/zero bs=4k seek=$[MLOC/4] count=$[128*256] of=/dev/mapper/$NAME
		# well, killing the first 80k of meta data should be enough for now...
		dd if=/dev/zero bs=4k seek=$[MLOC/4] count=20 of=/dev/mapper/$NAME
	fi
	sync
	echo .
	drbdadm up $RES
	# cat /proc/drbd
	echo "up'ed drbd $RES on $HOSTNAME"
}

drbdadm_up()								# {{{3
{
	: ${name:?unknown resource name} 
	drbdadm up $name
	# cat /proc/drbd
	echo "up'ed drbd $name on $HOSTNAME"
}

drbdadm_down()								# {{{3
{
	: ${name:?unknown resource name} 
	drbdadm down $name
	# cat /proc/drbd
	echo "down'ed drbd $name on $HOSTNAME"
}

drbd_wait_sync()							# {{{3
{
	: ${DEV:?unknown device name} 
	drbdsetup $DEV wait_connect -d 0 -t 0
	drbdsetup $DEV wait_sync -t 0
	# cat /proc/drbd
}

drbd_wait_peer_not_pri()						# {{{3
{
	: ${minor:?unknown minor number} 
	while true; do
		grep -q "^ *$minor:.*/Primary" /proc/drbd || break
		sleep 1
		# FIXME currently hardcoded timeout ...
		(( SECONDS > 30 )) && exit 1
	done
	exit 0
}

drbd_reattach()								# {{{3
{
	: ${DEV:?unknown device name} 
	: ${name:?unknown resource name} 
	if drbdsetup $DEV show | grep -q "^Lower device:.*null"; then
		# NO. drbdadm attach $name
		# But rather:
		drbdadm down $name
		drbdadm up $name
		echo "reattached $name on $HOSTNAME"
	fi
}

drbdadm_pri()
{
	: ${name:?unknown resource name} 
	: ${force:=}
	drbdadm $force primary $name
	echo "$name now Primary on $HOSTNAME"
}

drbdadm_sec()
{
	: ${name:?unknown resource name} 
	drbdadm secondary $name
	echo "$name now Secondary on $HOSTNAME"
}

#
# FileSystem        {{{2
########################

do_mount()
{
	: ${MNT:?unknown mount point} 
	: ${TYPE:?unknown fs type} 
	: ${DEV:?which device are you talkin about}
	mount -v -t ${TYPE%%_*} $DEV $MNT
}

do_umount()
{
	: ${MNT:?unknown mount point} 
	while grep -q " $MNT " /proc/mounts ; do
		umount -v $MNT/ && break
		fuser -vmk $MNT/ || true
		sleep 1
	done
}

mkfs_reiserfs_nomkfs() { echo "skipped mkreiserfs" ; }
mkfs_ext2_nomkfs()     { echo "skipped mke2fs"     ; }
mkfs_ext3_nomkfs()     { echo "skipped mke3fs"     ; }
mkfs_xfs_nomkfs()      { echo "skipped mkxfs"      ; }

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

#set -o errexit
set -o errexit $DEBUG
