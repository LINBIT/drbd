#!/bin/sh

SETSIZE=10000  #KBYTE
R_NODE=lha2  
L_NODE=lha1
CR_NODE=ha2
CL_NAME=ha1
RL_DEV=/dev/sda6
LL_DEV=/dev/sda6
DRBDSETUP=/usr/sbin/drbdsetup
MODPROBE=/sbin/modprobe
PROTOCOLS="B A"

ssh $CR_NODE $DRBDSETUP /dev/nb0 SEC

for PROT in $PROTOCOLS; do

  echo -n "P"
  sleep 1
  echo -n "r"
  $MODPROBE -r drbd
  ssh $CR_NODE $MODPROBE -r drbd
  sleep 1
  echo -n "o"
  $MODPROBE drbd
  ssh $CR_NODE $MODPROBE drbd

  ssh $CR_NODE $DRBDSETUP /dev/nb0 $RL_DEV $PROT $R_NODE $L_NODE
  $DRBDSETUP /dev/nb0 $LL_DEV $PROT $L_NODE $R_NODE

  sleep 1
  echo -n "t"
  $DRBDSETUP /dev/nb0 PRI

  echo -n "ocol $PROT: "
  time --format=%E ./send_n_sync.sh $SETSIZE;
done

#time ./send_n_sync.sh $SETSIZE




