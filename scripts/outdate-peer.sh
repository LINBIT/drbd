#!/bin/bash
#
#  outdate-peer.sh
#  This file is part of drbd by Philipp Reisner / Lars Ellenberg.
#

#
# It is expected that your clustermanager of choice brings its own
# implementation of this ... E.g. Heartbeat's variant should be able
# to use all of Heartbeat's communication pathes, including the
# serial connections.
#

# This script requires, that there is a password less ssh-key for
# root. You should not use such keys on a bigger scale. Only use
# it with the "from" option!
#
# How to setup SSH:
#
# 1. ssh-keygen -t dsa   (as root, on the first machine)
#    no passphrase!
#
# 2. go to the second machine, edit the file .ssh/authorized_keys2
#    Start a line with from="10.9.9.181,10.99.99.1" [content of id_dsa.pub]
#      Put the IPs of you first machine here, also the id_dsa.pub
#      is from the first machine All needs to be in a single line.
# 
# 3. ssh from the first machine to the second one, do this for all
#    IP addresses of the second machine. When doing this the first
#    time it asks you if it should ad the fingerprint to the list
#    of known hosts: Say yes here.
#
# 4. Do this a second time for each IP address, now it should not ask
#    any questions...
#
# Repeate this 4 steps for the other direction, BTW, you can not
# copy the file over, since you have two distrinct keys.. and also
# the IP addresses in the from="" part are different.
#

TIMEOUT=6

for P in "$@"; do
    if [ "$P" = "on" ]; then 
	EXP_HOST_NAME=1
	EXP_PEER_IP=0
	EXP_OWN_IP=0
    else
	if [ "$EXP_PEER_IP" = "1" ]; then 
	    PEER_IP="$PEER_IP $P"
	fi;
	if [ "$EXP_OWN_IP" = "1" ]; then 
	    OWN_IP="$OWN_IP $P"
	fi;
	if [ "$EXP_HOST_NAME" = "1" ]; then 
	    if [ "$P" != `uname -n` ]; then 
		EXP_PEER_IP=1
	    else
		EXP_OWN_IP=1
	    fi
	    EXP_HOST_NAME=0
	fi
    fi
done

if [ -z "$PEER_IP" -o -z "$OWN_IP" ]; then
    echo "USAGE: outdate-peer.sh on host1 IP IP ... on host2 IP IP ..."
    exit 10
fi

for IP in $PEER_IP; do
    ssh $IP drbdadm outdate r0 &
    SSH_PID="$SSH_PID $!"
done


SSH_CMDS_RUNNING=1
while [ "$SSH_CMDS_RUNNING" = "1" ] && [ $TIMEOUT -gt 0 ]; do
    sleep 1
    SSH_CMDS_RUNNING=0
    for P in $SSH_PID; do
	if [ -d /proc/$P ]; then SSH_CMDS_RUNNING=1; fi
    done
    TIMEOUT=$(( $TIMEOUT - 1 ))
done

RV=5
for P in $SSH_PID; do
    if [ -d /proc/$P ]; then
	kill $P
	wait $P
    else
	wait $P
	EXIT_CODE=$?

	# exit codes of drbdmeata outdate:
	# 5  -> is inconsistent
	# 0  -> is outdated
	# 17 -> outdate failed because peer is primary.
	# Unfortunately 20 can have other reasons too....

	if [ $EXIT_CODE -eq 5 ]; then RV=3; else
	    if [ $EXIT_CODE -eq 17 ]; then RV=6; else
		if [ $EXIT_CODE -eq 0 ]; then RV=4; else
		    echo "do not know about this exit code"
		fi
	    fi
	fi
    fi
done

# We return to DRBD - kernel driver:
#
# 6 -> peer is primary (and UpToDate)
# 5 -> peer is down / unreachable.
# 4 -> peer is outdated
# 3 -> peer is inconsistent

exit $RV

