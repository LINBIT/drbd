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

echo "This script is going to erase the first $SETSIZE of $LL_DEV @ $L_NODE "
echo "and $RL_DEV @ $R_NODE. "
echo "Continue ? [y/n] "
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
$DRBDSETUP /dev/nb0 $LL_DEV A $L_NODE $R_NODE -d $SETSIZE
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
$RSH $R_NODE $RDRBDSETUP /dev/nb0 $RL_DEV A $R_NODE $L_NODE -d $SETSIZE
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

echo "--------------- report --------------"
cat report
echo "-------------------------------------"
echo "Please send the report file to philipp@linuxfreak.com."
echo "     Thank you."
echo 
echo "PS: Do not forget to disable rsh again."




