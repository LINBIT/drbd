#!/usr/bin/env - /bin/bash
# $Id: T-003.sh,v 1.1.2.2 2004/06/07 13:58:27 lars Exp $

#
# Fail Secondary disk, reattach "healed" disk, Relocate Service.
# does work.
#

Start RS_1 Node_1

echo "FAIL Secondary DISK"
Fail_Disk Disk_2
sleep 30

echo "HEAL Secondary DISK"
Heal_Disk Disk_2
echo "REATTACH Secondary DISK"
on $Node_2: drbd_reattach minor=0 name=r0
echo "WAIT_SYNC"
on $Node_2: drbd_wait_sync minor=0

Reloc RS_1 Node_2
sleep 10

Stop RS_1
