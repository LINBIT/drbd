#!/usr/bin/env - /bin/bash

#
# Fail Secondary disk, reattach "healed" disk, Relocate Service.
# does work.
#

: ${RS_1:?no RS_1 defined...}

Start RS_1 Node_1

echo "FAIL Secondary DISK"
Fail_Disk Disk_2
sleep 30

echo "HEAL Secondary DISK"
Heal_Disk Disk_2
echo "REATTACH Secondary DISK"
on $Node_2: drbd_reattach DEV=/dev/${DRBD_DEVNAME}0 name=r0
echo "WAIT_SYNC"
on $Node_2: drbd_wait_sync DEV=/dev/${DRBD_DEVNAME}0

Reloc RS_1 Node_2
sleep 10

Stop RS_1
