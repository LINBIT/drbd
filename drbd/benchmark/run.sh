#!/bin/sh

echo
echo "Automatic DRBD performance measuring script."
echo "--------------------------------------------"
echo 

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
  exec ./run.sh;
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
OPTIONS="-t 50"

unset LC_ALL
unset LANG
unset LINGUAS

$RMMOD drbd 2> /dev/zero
$RSH $R_NODE $RMMOD drbd 2> /dev/zero

echo -n -e "DRBD Benchmark\n " > report
$DRBDSETUP 2>&1 | grep Version | sed -e "s/\  //g" >>report
echo " SETSIZE = $SETSIZE" >>report
echo >>report

##
# LOCAL DISK
##
echo -n -e "Node1:\n " >>report
uname -s -r -m >>report    
echo -n " " >>report
grep -i BogoMIPS /proc/cpuinfo >>report
echo "local disk"
echo -n " Disk write: " >>report
$DM -i /dev/zero -o $LL_DEV -s $SETSIZE -y -p >>report
echo -n " Drbd unconnected: " >>report
$INSMOD $MODULE
$DRBDSETUP /dev/nb0 disk $LL_DEV -d $SETSIZE
$DRBDSETUP /dev/nb0 net $L_NODE $R_NODE A 
$DRBDSETUP /dev/nb0 primary
$DM -i /dev/zero -o /dev/nb0 -s $SETSIZE -y -p >>report
$RMMOD drbd
echo >>report

##
# REMOTE DISK
##
echo -n -e "Node2:\n " >>report
$RSH $R_NODE uname -s -r -m >>report    
echo -n " " >>report
$RSH $R_NODE grep -i BogoMIPS /proc/cpuinfo >>report
echo "remote disk"
echo -n " Disk write: " >>report
$RSH $R_NODE $RDM -i /dev/zero -o $RL_DEV -s $SETSIZE -y -p >>report
echo -n " Drbd unconnected: " >>report
$RSH $R_NODE $INSMOD $RMODULE
$RSH $R_NODE $RDRBDSETUP /dev/nb0 disk $RL_DEV -d $SETSIZE
$RSH $R_NODE $RDRBDSETUP /dev/nb0 net $R_NODE $L_NODE A 
$RSH $R_NODE $RDRBDSETUP /dev/nb0 primary
$RSH $R_NODE $RDM -i /dev/zero -o /dev/nb0 -s $SETSIZE -y -p >>report
$RSH $R_NODE $RMMOD drbd
echo >>report

##
# NETWORK
##
echo "network"
echo "Network: " >>report
echo -n " Bandwidth: " >>report
$RSH $R_NODE $RDM -i /dev/zero -s $SETSIZE | $DM -o /dev/null -p >>report
echo -n " Latency: " >>report
ping -c 50 -f $R_NODE | grep round-trip >>report

echo -e "\nDrbd connected (writing on node1):" >>report
for PROT in $PROTOCOLS; do
  echo -n "Pr"
  $INSMOD $MODULE
  $RSH $R_NODE $INSMOD $RMODULE
  echo -n "o"
  $RSH $R_NODE $RDRBDSETUP /dev/nb0 disk $RL_DEV
  $RSH $R_NODE $RDRBDSETUP /dev/nb0 net $R_NODE $L_NODE $PROT -k
  $DRBDSETUP /dev/nb0 disk $LL_DEV
  $DRBDSETUP /dev/nb0 net $L_NODE $R_NODE $PROT -k
  $DRBDSETUP /dev/nb0 wait_connect $OPTIONS
  $RSH $R_NODE $RDRBDSETUP /dev/nb0 wait_connect $OPTIONS

  echo -n "t"

  sleep 2

  $DRBDSETUP /dev/nb0 primary

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
  $RSH $R_NODE $RDRBDSETUP /dev/nb0 disk $RL_DEV
  $RSH $R_NODE $RDRBDSETUP /dev/nb0 net $R_NODE $L_NODE $PROT -k
  $DRBDSETUP /dev/nb0 disk $LL_DEV
  $DRBDSETUP /dev/nb0 net $L_NODE $R_NODE $PROT -k
  $DRBDSETUP /dev/nb0 wait_connect $OPTIONS
  $RSH $R_NODE $RDRBDSETUP /dev/nb0 wait_connect $OPTIONS
  echo -n "t"

  sleep 2

  $RSH $R_NODE $RDRBDSETUP /dev/nb0 primary

  echo "ocol $PROT"
  
  echo -n " Protocol $PROT: " >>report
  $RSH $R_NODE $RDM -i /dev/zero -o /dev/nb0 -s $SETSIZE -y -p >>report

  sleep 1

  $RMMOD drbd
  $RSH $R_NODE $RMMOD drbd
  sleep 1;
done

echo "--------------- report --------------"
cat report
echo "-------------------------------------"
echo "Please send the report file to philipp.reisner@gmx.at."
echo "     Thank you."
echo 
echo "PS: Do not forget to disable rsh again."
