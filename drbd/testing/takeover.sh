#! /bin/bash

R_DRBD_DIR=/home/phil/drbd/
OTHER=hatest1
DEV=/dev/nb0
MNT=/mnt/ha0
RDRBDSETUP=$R_DRBD_DIR"user/drbdsetup"

mount $MNT
rm -rf $MNT/*
cp -vr /usr/src/linux $MNT/l
umount $MNT
../user/drbdsetup $DEV s
ssh $OTHER $RDRBDSETUP $DEV p
ssh $OTHER mount $MNT
ssh $OTHER rm -rf $MNT/*

