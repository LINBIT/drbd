#!/bin/sh

SETSIZE=10M
R_NODE=phil
L_NODE=alf
RL_DEV=/dev/sda6
LL_DEV=/dev/hdc6
R_DRBD_DIR=/home/philipp/src/uni/drbd-i386/
#---
INSMOD=/sbin/insmod
RMMOD=/sbin/rmmod
RSH=rsh
#---
PROTOCOLS="A B C"
DRBDSETUP=../user/drbdsetup
RDRBDSETUP=$R_DRBD_DIR"user/drbdsetup"
DM=./dm
RDM=$R_DRBD_DIR"benchmark/dm"
MODULE=../drbd/drbd.o
RMODULE=$R_DRBD_DIR"drbd/drbd.o"

unset LC_ALL
unset LANG
unset LINGUAS

$RMMOD drbd 2> /dev/zero
$RSH $R_NODE $RMMOD drbd 2> /dev/zero

echo "DRBD Benchmark" > report
echo "SETSIZE = $SETSIZE" >>report
echo >>report
echo -n -e "Node1:\n " >>report
uname -s -r -m >>report    
echo -n " " >>report
grep -i BogoMIPS /proc/cpuinfo >>report
echo "lokal disk"
echo -n " Disk write: " >>report
$DM -i /dev/zero -o $LL_DEV -s $SETSIZE -y -p >>report
echo -n " Drbd unconnected: " >>report
$INSMOD $MODULE
$DRBDSETUP /dev/nb0 $LL_DEV A $L_NODE $R_NODE -d 10240
$DRBDSETUP /dev/nb0 PRI
$DM -i /dev/zero -o /dev/nb0 -s $SETSIZE -y -p >>report
$RMMOD drbd
echo >>report

echo -n -e "Node2:\n " >>report
$RSH $R_NODE uname -s -r -m >>report    
echo -n " " >>report
$RSH $R_NODE grep -i BogoMIPS /proc/cpuinfo >>report
echo "remote disk"
echo -n " Disk write: " >>report
$RSH $R_NODE $RDM -i /dev/zero -o $RL_DEV -s $SETSIZE -y -p >>report
echo -n " Drbd unconnected: " >>report
$RSH $R_NODE $INSMOD $RMODULE
$RSH $R_NODE $RDRBDSETUP /dev/nb0 $RL_DEV A $R_NODE $L_NODE -d 10240
$RSH $R_NODE $RDRBDSETUP /dev/nb0 PRI
$RSH $R_NODE $RDM -i /dev/zero -o /dev/nb0 -s $SETSIZE -y -p >>report
$RSH $R_NODE $RMMOD drbd
echo >>report

echo "network"
echo "Network: " >>report
echo -n " Bandwith: " >>report
$RSH $R_NODE $RDM -i /dev/zero -s $SETSIZE | $DM -o /dev/null -p >>report
echo -n " Latency: " >>report
ping -c 50 -f $R_NODE | grep round-trip >>report

echo -e "\nDrbd connected (writing on node1):" >>report
for PROT in $PROTOCOLS; do
  echo -n "Pr"
  $INSMOD $MODULE
  $RSH $R_NODE $INSMOD $RMODULE
  echo -n "o"
  $RSH $R_NODE $RDRBDSETUP /dev/nb0 $RL_DEV $PROT $R_NODE $L_NODE
  $DRBDSETUP /dev/nb0 $LL_DEV $PROT $L_NODE $R_NODE
  echo -n "t"

  sleep 1

  $DRBDSETUP /dev/nb0 PRI

  echo "ocol $PROT"
  
  echo -n " Protocol $PROT: " >>report
  $DM -i /dev/zero -o /dev/nb0 -s $SETSIZE -y -p >>report

  sleep 1

  $RMMOD drbd
  $RSH $R_NODE $RMMOD drbd
  sleep 1;
done

echo -e "\nDrbd connected (writing on node2):" >>report
for PROT in $PROTOCOLS; do
  echo -n "Pr"
  $INSMOD $MODULE
  $RSH $R_NODE $INSMOD $RMODULE
  echo -n "o"
  $RSH $R_NODE $RDRBDSETUP /dev/nb0 $RL_DEV $PROT $R_NODE $L_NODE
  $DRBDSETUP /dev/nb0 $LL_DEV $PROT $L_NODE $R_NODE
  echo -n "t"

  sleep 1

  $RSH $R_NODE $RDRBDSETUP /dev/nb0 PRI

  echo "ocol $PROT"
  
  echo -n " Protocol $PROT: " >>report
  $RSH $R_NODE $RDM -i /dev/zero -o /dev/nb0 -s $SETSIZE -y -p >>report

  sleep 1

  $RMMOD drbd
  $RSH $R_NODE $RMMOD drbd
  sleep 1;
done

cat report



