#!/usr/bin/env - /bin/bash
# $Id: CTH_bash.sh,v 1.1.2.2 2004/05/27 17:46:58 lars Exp $

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

cat <<___
#
# ok, all up and configured, and fresh file systems created...
#
# now we can
#
#  start something on some node:
#     resource_Start_on_Node RS_1 Node_1
#
#  relocate it:
#     resource_relocate_to_Node RS_1 Node_2
#
#  stop it again:
#     resource_Stop RS_1
#
#  sleep \$for_a_while # ;-)
#
#  fail and heal hardware:
#     crash_Node    Node_#
#     wait_for_boot Node_#
#     fail_Link Link_#
#     heal_Link Link_#
#     fail_Disk Disk_#
#     heal_Disk Disk_#
#
___

# for example:
#   resource_Start_on_Node RS_1 Node_1
#   sleep 30
#   resource_relocate_to_Node RS_1 Node_2
#   sleep 30
#   resource_Stop RS_1
