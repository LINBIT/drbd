#!/usr/bin/env - /bin/bash
# $Id: CTH_bash.sh,v 1.1.2.8 2004/06/15 08:41:02 lars Exp $

# example for scripting failures
# 
# in contrast to generic_test.pl and the LGE_CTH perl modules, which are meant
# ot generate random hardware failures and resource relocations,
# this is meant to script a particular failure scenario.
#
# if you source this, you can use it interactively:
#   source CTH_bash.sh bloodymary.sh.conf CASE=interactive
#

[[ $- == *i* ]] && INTERACTIVE=true || INTERACTIVE=false

CONF=$1 CASE=$2
: ${CONF:?please tell me the config file of your choice}
: ${CASE:?please tell me the test case to run}

Run()
{
	source ./CTH_bash.helpers || return

	# get the configuration
	# YOU MUST GET THIS RIGHT !
	# source ./CTH_bash.conf # uml-minna.sh.conf
	# source ./bloodymary.sh.conf
	clear_env
	source $CONF              || return

	# verify
	# Dump_All
	# exit 0

	# get the generic test harness functions
	# DEBUG=-vx
	__I_MEAN_IT__=__YES__
	source ./functions.sh     || return

	boot_and_setup_nodes      || return

	cat <<-___
	#
	# ok, all up and configured, and fresh file systems created...
	#
	___

	trap 'ex=$?; echo "exit_code: $ex"' ERR # show exit codes != 0
	if [[ -e $CASE ]] ; then
		echo "now run CASE=$CASE"
		source $CASE || return
	fi

	return
}

set +e
if Run; then
	cat <<-___
	#--- $CASE ----
	#     PASSED
	#-----------------
	___
else
	echo "something went wrong. exit_code: $?"
fi

if $INTERACTIVE ; then
	cat <<-___
	#
	# now you can:
	#
	___
	Help
	Dump_RS
fi
