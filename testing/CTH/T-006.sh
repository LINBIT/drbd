#!/usr/bin/env - /bin/bash
# $Id: T-006.sh,v 1.1.2.2 2004/06/07 13:58:27 lars Exp $

#
# Fail Secondary disk, reattach "healed" disk, Relocate Service.
#
# in a loop. does work.
#
# not exactly "real world" since actually we'd need a "invalidate",
# because we put in a new and clean disk. 
# but this tests shows how drbd behaves when the primary disk fails
# and you configured "on-io-error Detach;"
#

# start it.
Start RS_1 Node_1
sleeptime=30
sleep $sleeptime

while true; do

	Fail_Disk Disk_2
	sleep $sleeptime

	Heal_Disk Disk_2
	on $Node_2: drbd_reattach minor=0 name=r0
	sleep $sleeptime
	# now wait for sync,
	# I don't want to bail out of the test early
	# because I fail the only good copy of the data ...
	on $Node_2: drbd_wait_sync minor=0

	Reloc RS_1 Node_2
	sleep $sleeptime

	# and reverse
	
	Fail_Disk Disk_1
	sleep $sleeptime

	Heal_Disk Disk_1
	on $Node_1: drbd_reattach minor=0 name=r0
	sleep $sleeptime
	on $Node_1: drbd_wait_sync minor=0

	Reloc RS_1 Node_1
	sleep $sleeptime

done
