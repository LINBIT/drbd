#!/usr/bin/env - /bin/bash
# $Id: CTH_bash.sh,v 1.1.2.5 2004/05/28 11:52:43 lars Exp $

# example for scripting failures
# 
# in contrast to generic_test.pl and the LGE_CTH perl modules, which are meant
# ot generate random hardware failures and resource relocations,
# this is meant to script a particular failure scenario.
#
# if you source this, you can use it interactively:
#   source CTH_bash.sh bloodymary.sh.conf CASE=interactive
#

CONF=$1 CASE=$2
: ${CONF:?please tell me the config file of your choice}
: ${CASE:?please tell me the test case to run}

source ./CTH_bash.helpers

# get the configuration
# YOU MUST GET THIS RIGHT !
# source ./CTH_bash.conf # uml-minna.sh.conf
# source ./bloodymary.sh.conf
clear_env
source $CONF

# verify
# Dump_All
# exit 0

# get the generic test harness functions
# DEBUG=-vx
__I_MEAN_IT__=__YES__
source ./functions.sh

trap 'echo "exit_code: $?"' ERR EXIT # show exit codes != 0
boot_and_setup_nodes

cat <<___
#
# ok, all up and configured, and fresh file systems created...
#
___
if [[ -e $CASE ]] ; then
	echo "now run CASE=$CASE"
	( source $CASE )
elif [[ $- == *i* ]] ; then
	set +errexit # disable this again.
	cat <<-___
	#
	# now you can:
	#
	___
	Help
	Dump_RS
fi
