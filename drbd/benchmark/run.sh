#!/bin/sh

SETSIZE=10000  #KBYTE
R_NODE=phil
L_NODE=alf
CR_NODE=phil
CL_NAME=alf
RL_DEV=/dev/sda6
LL_DEV=/dev/hdc6
#R_NODE=alf
#L_NODE=phil
#CR_NODE=alf
#CL_NAME=phil
#RL_DEV=/dev/hdc6
#LL_DEV=/dev/sda6

DRBDSETUP=/usr/sbin/drbdsetup
MODPROBE=/sbin/modprobe
PROTOCOLS="A"
RSH=rsh

$RSH $CR_NODE $DRBDSETUP /dev/nb0 SEC

for PROT in $PROTOCOLS; do

  echo -n "P"
  sleep 1
  echo -n "r"
  $MODPROBE -r drbd
  $RSH $CR_NODE $MODPROBE -r drbd
  sleep 1
  echo -n "o"
  $MODPROBE drbd
  $RSH $CR_NODE $MODPROBE drbd

  $RSH $CR_NODE $DRBDSETUP /dev/nb0 $RL_DEV $PROT $R_NODE $L_NODE
  $DRBDSETUP /dev/nb0 $LL_DEV $PROT $L_NODE $R_NODE

  sleep 1
  echo -n "t"
  $DRBDSETUP /dev/nb0 PRI

  echo -n "ocol $PROT: "
  time --format=%E ./send_n_sync.sh $SETSIZE;
done

#time ./send_n_sync.sh $SETSIZE




