#!/usr/bin/env - /bin/bash
# $Id: T-006.sh,v 1.1.2.2 2004/06/07 13:58:27 lars Exp $

#
# Fail Secondary disk, reattach "healed" disk, Relocate Service.
#
# in a loop. does work.
#
# this tests shows how drbd behaves when the Secondary disk fails
# and you configured "on-io-error Detach;"
#

: ${RS_1:?no RS_1 defined...}

# start it.
Start RS_1 Node_1
sleeptime=30
sleep $sleeptime

while true; do

	Fail_Disk Disk_2
	sleep $sleeptime

	Heal_Disk Disk_2
	on $Node_2: drbd_reattach DEV=/dev/${DRBD_DEVNAME}0 name=r0
	sleep $sleeptime
	# now wait for sync,
	# I don't want to bail out of the test early
	# because I fail the only good copy of the data ...
	on $Node_2: drbd_wait_sync DEV=/dev/${DRBD_DEVNAME}0

	Reloc RS_1 Node_2
	sleep $sleeptime

	# and reverse
	
	Fail_Disk Disk_1
	sleep $sleeptime

	Heal_Disk Disk_1
	on $Node_1: drbd_reattach DEV=/dev/${DRBD_DEVNAME}0 name=r0
	sleep $sleeptime
	on $Node_1: drbd_wait_sync DEV=/dev/${DRBD_DEVNAME}0

	Reloc RS_1 Node_1
	sleep $sleeptime

done
