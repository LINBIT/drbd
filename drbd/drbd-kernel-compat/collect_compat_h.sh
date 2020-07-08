#!/bin/bash

export LC_ALL=C LANG=C LANGUAGE=C
#
# Do not try to use this unless you are on LINBIT's internal network
# and have ssh access to lbbuild@thank.linbit
#
N_CONFIGS=0
N_UNIQUE=0
N_PRESERVED=0

if [ -z "$LBBUILD_CI_BUILD" ]; then
	COMPAT_HEADERS_PATH=/home/lbbuild/lbbuild/localpkgs/drbd-9-compat-latest
else
	COMPAT_HEADERS_PATH=/home/lbbuild/lbbuild/localpkgs/ci/drbd
fi

if [ "$(uname -n)" = "thank" ]; then
	FILES=$((cd $COMPAT_HEADERS_PATH; find . -name "compat.h*" \
		| tar -T - -czf -) | tar xzvf -)
elif ping -c1 thank.linbit > /dev/null 2>&1; then
	FILES=$(ssh lbbuild@thank.linbit \
		"cd $COMPAT_HEADERS_PATH; find . -name "compat.h*" | tar -T - -czf -" \
		| tar xzvf -)
else
	echo "ERROR: you don't seem to have access to LINBIT's internal network."
	echo "Your tarball will not contain any pre-computed kernel backwards"
	echo "compatibility patches."
	exit 1
fi

./build_cocci_cache.sh $FILES
