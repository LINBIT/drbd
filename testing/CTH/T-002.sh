#!/usr/bin/env - /bin/bash

#
# Fail Disk on Primary, Relocate Service, reattach on now Secondary.
# does work.
# 

: ${RS_1:?no RS_1 defined...}

Start RS_1 Node_1

sleep 10

Fail_Disk Disk_1
sleep 5

Reloc RS_1 Node_2
sleep 5

Heal_Disk Disk_1
on $Node_1: drbd_reattach DEV=/dev/${DRBD_DEVNAME}0 name=r0
sleep 10
on $Node_1: drbd_wait_sync DEV=/dev/${DRBD_DEVNAME}0

Reloc RS_1 Node_1
sleep 10

Stop RS_1
