#!/usr/bin/env - /bin/bash
# $Id: T-007.sh,v 1.1.2.1 2004/06/15 08:41:02 lars Exp $

#
# Fail Link; Heal Link; wait for sync; Relocate service.
#
# in a loop. does work.
#

sleeptime=20

# start it.
Start RS_1 Node_1
sleep 10

iter=2
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

	Reloc RS_1 Node_1
	sleep $sleeptime

	echo "===> $iter iterations to go ... <==="
done

Stop RS_1

Drbd_MD5_diff Drbd_1 > md5sum.r0.diff
