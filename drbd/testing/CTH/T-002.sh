#!/usr/bin/env - /bin/bash
# $Id: T-002.sh,v 1.1.2.4 2004/06/03 11:05:53 lars Exp $

#
# Fail Disk on Primary, Relocate Service, reattach on now Secondary.
# does work.
# 

Start RS_1 Node_1

sleep 10

Fail_Disk Disk_1
sleep 5

Reloc RS_1 Node_2
sleep 5

Heal_Disk Disk_1
on $Node_1: drbd_reattach minor=0 name=r0
sleep 10
on $Node_1: drbd_wait_sync minor=0

Reloc RS_1 Node_1
sleep 10

Stop RS_1
