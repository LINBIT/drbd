#!/usr/bin/env - /bin/bash
# $Id: T-007.sh,v 1.1.2.2 2004/06/17 01:35:52 lars Exp $

#
# Fail Link; Heal Link; wait for sync; Relocate service.
#
# in a loop. does work.
#

sleeptime=30

# start it.
Start RS_1 Node_1
sleep 10

iter=150
while (( iter-- )); do

	Fail_Link Link_1
	sleep $sleeptime

	Heal_Link Link_1
	SECONDS=0
	on $Node_1: drbd_wait_sync minor=0
	if (( sleeptime - SECONDS > 0)) ; then
		sleep $(( sleeptime - SECONS ))
	fi

	Reloc RS_1 Node_2
	sleep $sleeptime

	Fail_Link Link_1
	sleep $sleeptime

	Heal_Link Link_1
	SECONDS=0
	on $Node_2: drbd_wait_sync minor=0
	if (( sleeptime - SECONDS > 0)) ; then
		sleep $(( sleeptime - SECONS ))
	fi

	Stop RS_1
	if (( iter % 10 == 0 )) ; then
		Drbd_MD5_diff Drbd_1 > md5sum.r0.diff.$iter
	fi
	Start RS_1 Node_1

	sleep $sleeptime

	echo "===> $iter iterations to go ... <==="
done

Stop RS_1
