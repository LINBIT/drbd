#!/usr/bin/env - /bin/bash
# $Id: T-006.sh,v 1.1.2.1 2004/06/03 11:05:53 lars Exp $

#
# Fail Secondary disk, reattach "healed" disk, Relocate Service.
#
# in a loop. does NOT work.
# pending_cnt gets confused!
#
# not exactly "real world" since actually we'd need a "invalidate",
# because we put in a new and clean disk. 
# but this tests shows how drbd behaves when the primary disk fails
# and you configured "on-io-error Detach;"
#

# start it.
Start RS_1 Node_1
sleep 30

while true; do

	Fail_Disk Disk_2
	sleep 30

	Heal_Disk Disk_2
	on $Node_1: drbd_reattach minor=0 name=r0
	sleep 30
	# now wait for sync,
	# I don't want to bail out of the test early
	# because I fail the only good copy of the data ...
	on $Node_1: drbd_wait_sync minor=0

	Reloc RS_1 Node_2
	sleep 30

	# and reverse
	
	Fail_Disk Disk_1
	sleep 30

	Heal_Disk Disk_1
	on $Node_2: drbd_reattach minor=0 name=r0
	sleep 30
	on $Node_2: drbd_wait_sync minor=0

	Reloc RS_1 Node_1
	sleep 30

done
