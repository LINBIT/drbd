#!/usr/bin/env - /bin/bash
# $Id: CTH_bash.sh,v 1.1.2.1 2004/05/27 12:44:18 lars Exp $

# example for scripting failures
# 
# in contrast to generic_test.pl and the LGE_CTH perl modules, which are meant
# ot generate random hardware failures and resource relocations,
# this is meant to script a particular failure scenario.
#

source ./CTH_bash.helpers

# get the configuration
# YOU MUST GET THIS RIGHT !
source ./CTH_bash.conf

# verify
# Dump_All
# exit 0

# get the generic test harness functions
# DEBUG=-vx
__I_MEAN_IT__=__YES__
source ./functions.sh

boot_and_setup_nodes

#
# ok, all up and configured.
# now we can
#
#  start something on some node:
#     on $Node_#: drbdadm_pri   name=r#
#     on $Node_#: mkfs_reiserfs DEV=/dev/nb#
#     on $Node_#: do_mount      DEV=/dev/nb# TYPE=resiserfs MNT=/mnt/ha#
#     on $Node_#: wbtest_start  MNT=/mnt/ha#
#
#  stop it again:
#     on $Node_#: generic_test_stop MNT=/mnt/ha#
#     on $Node_#: do_umount     MNT=/mnt/ha#
#     on $Node_#: drbdadm_sec   name=r#
#
#  sleep $for_a_while
#
#  fail and heal hardware:
#     crash_Node Node_#
#     fail_Link Link_#
#     heal_Link Link_#
#     fail_Disk Disk_#
#     heal_Disk Disk_#
# 
