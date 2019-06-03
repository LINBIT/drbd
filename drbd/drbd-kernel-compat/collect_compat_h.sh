#!/bin/bash

#
# Do not try to use this unless you are on LINBIT's internal network
# and have ssh access to lbbuild@thank.linbit
#
N_CONFIGS=0
N_UNIQUE=0
FILES=$(ssh lbbuild@thank \
	'cd lbbuild/localpkgs/drbd-9.0.18-1; find . -name "compat.h*" | tar -T - -czf -' \
	| tar xzvf -)

rm -rf cocci_cache/*

for F in $FILES; do
    MD5SUM_OUTPUT=$(md5sum $F)
    MD5SUM=${MD5SUM_OUTPUT%% *}
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
    if test -e cocci_cache/$MD5SUM/kernelrelease.txt; then
	SEP=" "
    else
	SEP=""
    fi
    echo -n "$SEP$KERNELRELEASE" >> cocci_cache/$MD5SUM/kernelrelease.txt

    # Progress
    N_CONFIGS=$((N_CONFIGS + 1))
    printf "%3d %3d %-60s\r" $N_CONFIGS $N_UNIQUE $F
done

# Trailing newline for kernelrelease.txt
for F in cocci_cache/*/kernelrelease.txt; do
    echo "" >> $F
done

printf "%3d config.h processed, %d unique found                   \n" $N_CONFIGS $N_UNIQUE
