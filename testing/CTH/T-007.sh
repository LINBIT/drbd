#!/usr/bin/env - /bin/bash

#
# Fail Link; Heal Link; wait for sync; Relocate service.
# every 10th iteration, compare md5sums of lower level devices.
#
# in a loop. does work.
#

: ${RS_1:?no RS_1 defined...}

sleeptime=30

# FIXME incorporate properly into Drbd_MD5_diff in CTH_bash.helpers
Compare()
{
	out=md5sum.r0.diff.$iter
	echo "==> compare checksums of lower level devices"
	Drbd_MD5_diff Drbd_1 > $out || true
	last_line=$(sed -ne 's/^md probably starts at blocknr //p;2q' < $out)
	first_chunk=$(sed -ne '1,4d;s/^@@ -\([0-9]\+\),.*/\1/p;5q' < $out)
	if (( first_chunk > last_line )) ; then
		echo "no block differences in data section."
	else
		echo -n "number of block differences in data section: "
		if sed -e "1,4d;/^. *$last_line\t/q" $out | grep -c "^[+-]" ; then
			echo "oops. stopping here."
			echo "you want to have a look at '$out' yourself"
			exit 1
		fi
	fi
}

# start it.
Start RS_1 Node_1
sleep 10

iter=150
while (( iter-- )); do

	Fail_Link Link_1
	sleep $sleeptime

	Heal_Link Link_1
	SECONDS=0
	on $Node_1: drbd_wait_sync DEV=/dev/${DRBD_DEVNAME}0
	if (( sleeptime - SECONDS > 0)) ; then
		sleep $(( sleeptime - SECONS ))
	fi

	Reloc RS_1 Node_2
	sleep $sleeptime

	Fail_Link Link_1
	sleep $sleeptime

	Heal_Link Link_1
	SECONDS=0
	on $Node_2: drbd_wait_sync DEV=/dev/${DRBD_DEVNAME}0
	if (( sleeptime - SECONDS > 0)) ; then
		sleep $(( sleeptime - SECONS ))
	fi

	Stop RS_1
	if (( iter % 10 == 0 )) ; then
		Compare
	fi
	Start RS_1 Node_1

	sleep $sleeptime

	echo "===> $iter iterations to go ... <==="
done

Stop RS_1
