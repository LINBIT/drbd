#!/bin/bash

#
# Do not try to use this unless you are on LINBIT's internal network
# and have ssh access to lbbuild@thank.linbit
#
N_CONFIGS=0
N_UNIQUE=0
N_PRESERVED=0

if [ "$(uname -n)" = "thank" ]; then
	FILES=$((cd /home/lbbuild/lbbuild/localpkgs/drbd-9-compat-latest; find . -name "compat.h*" \
		| tar -T - -czf -) | tar xzvf -)
elif ping -c1 thank > /dev/null 2>&1; then
	FILES=$(ssh lbbuild@thank \
		"cd /home/lbbuild/lbbuild/localpkgs/drbd-9-compat-latest; find . -name "compat.h*" | tar -T - -czf -" \
		| tar xzvf -)
else
	echo "ERROR: you don't seem to have access to LINBIT's internal network."
	echo "Your tarball will not contain any pre-computed kernel backwards"
	echo "compatibility patches."
	exit 1
fi


mkdir -p cocci_cache.previous
for F in cocci_cache/*; do
    test -d $F && mv $F cocci_cache.previous/
done

for F in $FILES; do
    PREV=false
    N_CONFIGS=$((N_CONFIGS + 1))
    MD5SUM_OUTPUT=$(md5sum $F)
    MD5SUM=${MD5SUM_OUTPUT%% *}

    if test -e cocci_cache.previous/$MD5SUM; then
	mv cocci_cache.previous/$MD5SUM cocci_cache/
	PREV=true
	# Maybe we can preserves a compat.patch
	N_PRESERVED=$((N_PRESERVED + 1))
	N_UNIQUE=$((N_UNIQUE + 1))
    fi

    if test ! -e cocci_cache/$MD5SUM; then
	mkdir cocci_cache/$MD5SUM
	mv $F cocci_cache/$MD5SUM/compat.h
	NEW_MD5SUMS="$NEW_MD5SUMS $MD5SUM"
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

    if $PREV; then
	# Leave kernrelease.txt untouched
	continue
    fi

    KERNELRELEASE=${F#*compat.h.}
    if test -e cocci_cache/$MD5SUM/kernelrelease.txt; then
	SEP=" "
    else
	SEP=""
    fi
    echo -n "$SEP$KERNELRELEASE" >> cocci_cache/$MD5SUM/kernelrelease.txt

    # Progress
    printf "%3d %3d %-60s\r" $N_CONFIGS $N_UNIQUE $F
done

# Trailing newline for kernelrelease.txt
for MD5SUM in $NEW_MD5SUMS; do
    F=cocci_cache/$MD5SUM/kernelrelease.txt
    echo "" >> $F
done

shopt -s nullglob
REMOVED_A=(cocci_cache.previous/*)
N_REMOVED=${#REMOVED_A[@]}
rm -rf cocci_cache.previous

printf "%3d config.h processed, %d unique found, (%d preserved, %d removed)      \n" \
       $N_CONFIGS $N_UNIQUE $N_PRESERVED $N_REMOVED
