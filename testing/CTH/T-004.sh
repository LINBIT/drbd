#!/usr/bin/env - /bin/bash

#
# Fail Disk on Primary, Relocate Service, reattach on now Secondary,
# Fail same Disk *again* during synch,
# reattach again,
# wait for sync,
# done.
#
# does work.
#

: ${RS_1:?no RS_1 defined...}

Start RS_1 Node_1

sleep 2

Fail_Disk Disk_1

# reattaching on Primary currently not possible.

sleep 2
Reloc RS_1 Node_2

sleep 30 # so we have something to sync...

# reattaching a broken device does not work, because of a race during
# bitmap handshake... currently it may even cause both nodes to hang!
# # not yet. Heal_Disk Disk_1
# # see what happens:
# on $Node_1: drbd_reattach DEV=/dev/${DRBD_DEVNAME}0 name=r0

# attaching a good disk *does* work
Heal_Disk Disk_1
on $Node_1: drbd_reattach DEV=/dev/${DRBD_DEVNAME}0 name=r0

sleep 4

# now FAIL disk again, during sync,
# but after handshake...
# does work, too.

Fail_Disk Disk_1
sleep 10

Heal_Disk Disk_1
on $Node_1: drbd_reattach DEV=/dev/${DRBD_DEVNAME}0 name=r0
on $Node_1: drbd_wait_sync DEV=/dev/${DRBD_DEVNAME}0

Stop RS_1
