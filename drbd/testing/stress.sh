#!/bin/sh

if [ -e config ]; 
  then source config;
else
  echo "We need to write a config file first. You will have to answer"
  echo "6 questions about your setup."
  echo
  echo "*  You need to run this script as root."
  echo "*"
  echo "*  This script needs to make rsh connections to your second node,"
  echo "*  without using a passwort!"
  echo "*"
  echo "*  You can setup this by doing this on node2:"
  echo "*     'ALL: node1' in /etc/hosts.allow"
  echo "*     'shell stream ..... in.rshd' in /etc/inetd.conf"
  echo "*     'node1' in /root/.rhosts"
  echo
  echo "What is the name of your (local) machine (or IP address of the"
  echo "interface you want to use) ? "
  read L_NODE
  echo "What is the name of your remote machine (or IP address of the"
  echo "interface you want to use) ? "
  read R_NODE
  echo "Which disk device you want to use on your (local) machine? (/dev/xyz) "
  read LL_DEV
  echo "Which disk device you want to use on your remote machine? (/dev/xyz) "
  read RL_DEV
  echo "Where is the source directory on the remote machine? (/home/xy/drbd/) "
  read R_DRBD_DIR
  echo "Size for write preformance tests? (If you do not know enter '10M') "
  read SETSIZE
  echo
  echo "Is everything correct? [y/n] "
  read CORR
  if [ $CORR = "Y" -o $CORR = "y" ];
    then
      echo "L_NODE=$L_NODE" >config
      echo "LL_DEV=$LL_DEV" >>config
      echo "R_NODE=$R_NODE" >>config
      echo "RL_DEV=$RL_DEV" >>config
      echo "R_DRBD_DIR=$R_DRBD_DIR" >>config
      echo "SETSIZE=$SETSIZE" >>config;
  fi
  exec ./stress.sh;
fi

echo "                     !!! WARNING !!!"
echo
echo "This test will destroy the following partitions:"
echo "   $L_NODE::$LL_DEV"
echo "   $R_NODE::$RL_DEV"
echo "After the test is run, you will need to run mkfs on these"
echo "partitions in order to use them again."
echo
echo "PLEASE MAKE SURE YOU HAVE BACKED UP ANY DATA YOU NEED FROM"
echo "THESE PARTITIONS!"
echo
echo "Continue (and destroy these partitions) ? [y/n] "
read CONT
if [ $CONT != "Y" -a $CONT != "y" ];
  then exit 0;
fi

INSMOD=/sbin/insmod
RMMOD=/sbin/rmmod
RSH=rsh
#---
DRBDSETUP=../user/drbdsetup
RDRBDSETUP=$R_DRBD_DIR"user/drbdsetup"
DM=../benchmark/dm
RDM=$R_DRBD_DIR"benchmark/dm"
MODULE=../drbd/drbd.o
RMODULE=$R_DRBD_DIR"drbd/drbd.o"
OPRTIONS="-t 1"
PROT="C"

unset LC_ALL
unset LANG
unset LINGUAS

$RMMOD drbd 2> /dev/zero
$RSH $R_NODE $RMMOD drbd 2> /dev/zero

sleep 1

$INSMOD $MODULE
$RSH $R_NODE $INSMOD $RMODULE

sleep 1

$RSH $R_NODE $RDRBDSETUP /dev/nb0 $RL_DEV $PROT $R_NODE $L_NODE $OPTIONS
$DRBDSETUP /dev/nb0 $LL_DEV $PROT $L_NODE $R_NODE $OPTIONS

sleep 1

$DRBDSETUP /dev/nb0 PRI

$DM -i /dev/zero -o /dev/nb0 -s $SETSIZE -y -p &
$RSH $R_NODE $RDM -i /dev/zero -s $SETSIZE | $DM -o /dev/null -p

wait
sleep 1

$RMMOD drbd 2> /dev/zero
$RSH $R_NODE $RMMOD drbd 2> /dev/zero
