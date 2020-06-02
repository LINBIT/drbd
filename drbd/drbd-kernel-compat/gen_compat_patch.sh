#!/bin/bash

MIN_SPATCH_VERSION=1.0.8
[[ ${V:-0} != 0 ]] && set -x

# test if the version $1 is greater (more recent) than $2.
function version_gt() {
	test "$(printf '%s\n' "$@" | sort -V | head -n 1)" != "$1"
}

function spatch_is_recent() {
	ver=$(spatch --version | head -1 | sed -rn 's/^spatch version ([[:digit:]]\.[[:digit:]]\.[[:digit:]]).*/\1/p')
	! version_gt $MIN_SPATCH_VERSION $ver
}

function die_no_spatch() {
   echo "ERROR: no suitable spatch found in \$PATH. Install package 'coccinelle'!"
   exit 1
}

# generate compat patches by using the cache,
# or using spatch,
# or using curl to fetch it from spatch-as-a-service

compat_patch=$1
shift

[[ $compat_patch = drbd-kernel-compat/cocci_cache/*/compat.patch ]] || exit 1

incdir=${compat_patch%/compat.patch}
chksum=${incdir##*/}

set -e

if test -e .compat_patches_applied; then
    echo "Removing compat patches"
    patch -R -p0 --batch < .compat_patches_applied
    rm -f .compat_patches_applied
fi

if ! spatch_is_recent; then
    echo "INFO: spatch not recent enough, need spatch version >= $MIN_SPATCH_VERSION"
fi

if hash spatch && spatch_is_recent; then
    K=$(cat $incdir/kernelrelease.txt)
    echo "  GENPATCHNAMES   "$K
    gcc -I $incdir -o $incdir/gen_patch_names -std=c99 drbd-kernel-compat/gen_patch_names.c
    $incdir/gen_patch_names > $incdir/applied_cocci_files.txt
    rm $incdir/gen_patch_names
    rm -f $incdir/.compat.cocci
    rm -f $incdir/.compat.patch
    rm -f $incdir/.spatch.tty.out
    for F in $(cat $incdir/applied_cocci_files.txt); do
	if [ -e drbd-kernel-compat/cocci/$F.cocci ] ; then
	    cat drbd-kernel-compat/cocci/$F.cocci >> $incdir/.compat.cocci
	else
	    cat drbd-kernel-compat/patches/$F.patch >> $incdir/.compat.patch
	fi
	sed -e "s:@COMPAT_PATCH_NAME@:$F:g" \
		< drbd-kernel-compat/cocci/debugfs_compat_template.cocci.in \
		>> $incdir/.compat.cocci
    done
    if [ -e $incdir/.compat.cocci ]; then
	echo "  SPATCH   $chksum  "$K
	# Note: $* (or $@) is NOT make magic variable now, this is a shell script
	# make $@, the target file, was passed as $1, and is now $compat_patch
	# make $^, the source (and header) files spatch should operate on,
	# are "the rest of the shell argument array", so after shifting the first
	# argument away this is shell $@ respectively $* now.
	# we know we don't have white-space in the argument list

	command="spatch --sp-file $incdir/.compat.cocci $* --macro-file drbd-kernel-compat/cocci_macros.h --very-quiet > $compat_patch.tmp 2> $incdir/.spatch.stderr;"

	if test -t 0; then
	    $SHELL -c "$command"
	else
	    # spatch is broken in a way: it "requires" a tty.
	    # provide a tty using "script", so I can have several spatch in parallel.
	    # They may ignore INT and TERM; if you have to, use HUP.
	    </dev/null &> /dev/null script --append $incdir/.spatch.tty.out --return --quiet --command "$command"
	fi
    else
	echo "  SPATCH   $chksum  "$K" - nothing to do"
	touch $compat_patch.tmp
    fi
    if [ -e $incdir/.compat.patch ]; then
	cat $incdir/.compat.patch >> $compat_patch.tmp
    fi
    mv $compat_patch.tmp $compat_patch
    rm -f $incdir/.compat.cocci
    rm -f $incdir/.compat.patch
else
	if test -e ../.git; then
		echo "  INFO: not trying spatch-as-a-service because you are trying"
		echo "  to build DRBD from a git checkout. Please install a suitable"
		echo "  version of coccinelle (>1.0.8) or try building from a"
		echo "  release tarball."
		die_no_spatch
	fi

	if [[ $SPAAS != true ]]; then
		echo "  INFO: spatch-as-a-service was disabled by your package"
		echo "  maintainer (\$SPAAS = false). Install a suitable version"
		echo "  of coccinelle (>1.0.8) or allow spatch-as-a-service by"
		echo "  setting \$SPAAS = true"
		die_no_spatch
	fi

    echo "  INFO: no suitable spatch found; trying spatch-as-a-service;"
    echo "  be patient, may take up to 10 minutes"
    echo "  if it is in the server side cache it might only take a second"
    echo "  SPAAS    $chksum"

    # check if SPAAS is even reachable
    if ! curl -fsS https://drbd.io:2020/api/v1/hello; then
        echo "  ERROR: SPAAS is not reachable! Please check if your network"
        echo "  configuration or some firewall prohibits access to "
        echo "  https://drbd.io:2020."
        exit 1
    fi

    REL_VERSION=$(sed -ne '/^\#define REL_VERSION/{s/^[^"]*"\([^ "]*\).*/\1/;p;q;}' linux/drbd_config.h)
    rm -f $compat_patch.tmp.header $compat_patch.tmp
    if ! base64 $incdir/compat.h |
	curl -T - -X POST -o $compat_patch.tmp -D $compat_patch.tmp.header -f \
	    https://drbd.io:2020/api/v1/spatch/$REL_VERSION
    then
	ex=${PIPESTATUS[*]}
	(
	echo "=== pipestatus: $ex"
	cat $compat_patch.tmp.header $compat_patch.tmp
	printf "\n===\n\n"
	) >&2
	exit ${ex##* }
    else
	mv $compat_patch.tmp $compat_patch
    fi
    echo "  You can create a new .tgz including this pre-computed compat patch"
    echo "  by calling \"make unpatch ; echo drbd-$REL_VERSION/drbd/$compat_patch >>.filelist ; make tgz\""
fi
