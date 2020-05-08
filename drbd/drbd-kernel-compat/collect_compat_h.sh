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

mkdir -p cocci_cache
mkdir -p cocci_cache.previous
for F in cocci_cache/*; do
    test -d $F && mv $F cocci_cache.previous/
done

for F in $FILES; do
    N_CONFIGS=$((N_CONFIGS + 1))
    MD5SUM_OUTPUT=$(md5sum $F)
    MD5SUM=${MD5SUM_OUTPUT%% *}

    if test -e cocci_cache.previous/$MD5SUM; then
	mv cocci_cache.previous/$MD5SUM cocci_cache/
	# Maybe we can preserves a compat.patch
	N_PRESERVED=$((N_PRESERVED + 1))
	N_UNIQUE=$((N_UNIQUE + 1))
    fi

    if test ! -e cocci_cache/$MD5SUM; then
	mkdir cocci_cache/$MD5SUM
	mv $F cocci_cache/$MD5SUM/compat.h
	N_UNIQUE=$((N_UNIQUE + 1))
    else
	rm $F
    fi

    # clean up directory if already empty
    D="${F%/*}"
    while [ -n "$D" -a "$D" != "." ]; do
	rmdir --ignore-fail-on-non-empty $D
	D="${D%/*}"
    done

    KERNELRELEASE=${F#*compat.h.}
    echo "$KERNELRELEASE" >> cocci_cache/$MD5SUM/kernelrelease.txt

    ln -f -s -T ../cocci_cache/$MD5SUM l/$KERNELRELEASE

    # Progress
    printf "%3d %3d %-60s\r" $N_CONFIGS $N_UNIQUE $F
done

# sort/unique kernelrelease.txt
for F in cocci_cache/*/kernelrelease.txt; do
    printf "%s\n" $(cat $F) | sort -u > $F.new
    mv $F.new $F
done

shopt -s nullglob
REMOVED_A=(cocci_cache.previous/*)
N_REMOVED=${#REMOVED_A[@]}
rm -rf cocci_cache.previous

printf "%3d config.h processed, %d unique found, (%d preserved, %d removed)      \n" \
       $N_CONFIGS $N_UNIQUE $N_PRESERVED $N_REMOVED
