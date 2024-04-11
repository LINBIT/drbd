#!/bin/bash

MIN_SPATCH_VERSION=1.0.8
[[ ${V:-0} != [02] ]] && set -x

# to be passed in via environment
: ${sources[@]?}
: ${compat_patch?}
: ${chksum?}

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

[[ $compat_patch = drbd-kernel-compat/cocci_cache/*/compat.patch ]] || exit 1

set -e

if test -e .compat_patches_applied; then
	echo "Removing compat patches"
	patch -R -p0 --batch --reject-file=- < .compat_patches_applied
	rm -f .compat_patches_applied
fi

if ! spatch_is_recent; then
	echo "INFO: spatch not recent enough, need spatch version >= $MIN_SPATCH_VERSION"
fi

if hash spatch && spatch_is_recent; then
	K=$(cat $incdir/kernelrelease.txt || echo unknown kernel release)
	echo "  GENPATCHNAMES   "$K
	gcc -I $incdir -o $incdir/gen_patch_names -std=c99 drbd-kernel-compat/gen_patch_names.c
	$incdir/gen_patch_names > $incdir/applied_cocci_files.txt
	rm $incdir/gen_patch_names
	# truncat them all
	: > $incdir/.compat.cocci
	: > $incdir/.compat.cocci.tmp
	: > $incdir/.compat.patch
	: > $incdir/.compat.patch.tmp
	rm -f $incdir/.spatch.tty.out

	for F in $(cat $incdir/applied_cocci_files.txt); do
		F_cocci=drbd-kernel-compat/cocci/$F.cocci
		if [ -e $F_cocci ] ; then
			(
			# so you can match spatch warnings to cocci source files
			dashes=${F_cocci//?/-}
			printf "\n// -%s-\n//  %s\n// -%s-\n" "$dashes" "$F_cocci" "$dashes"
			cat $F_cocci
			) >> $incdir/.compat.cocci.tmp
		else
			F_patch=drbd-kernel-compat/patches/$F.patch
			cat $F_patch >> $incdir/.compat.patch.tmp
		fi
		sed -e "s:@COMPAT_PATCH_NAME@:$F:g" \
			< drbd-kernel-compat/cocci/debugfs_compat_template.cocci.in \
			>> $incdir/.compat.cocci.tmp
	done

	mv $incdir/.compat.cocci.tmp $incdir/.compat.cocci
	mv $incdir/.compat.patch.tmp $incdir/.compat.patch

	if [ -s $incdir/.compat.cocci ]; then
		# sources=( ... ) passed in via environment
		echo "	SPATCH	 $chksum  "$K
		set +e
		spatch --sp-file "$incdir/.compat.cocci" "${sources[@]}" \
			--macro-file drbd-kernel-compat/cocci_macros.h \
			--very-quiet \
			--all-includes \
			${SPATCH_DEBUG:+ --debug} \
			> "$compat_patch.tmp" \
			2> "$incdir/.spatch.stderr"
		ex=$?
		# if [[ $ex != 0 ]] || [[ ${V-0} != 0 ]] ; then
		# I want to see the spatch warnings, even without V=...
		if test -s $incdir/.spatch.stderr ; then
			echo "	  $incdir/.compat.cocci" >&2
			sed -e "s/^/	: /" < "$incdir/.spatch.stderr" >&2
			# spatch warnings fatal? not yet.
			# exit 1
		fi
		[[ $ex != 0 ]] && exit $ex
		set -e
	else
		echo "	SPATCH	 $chksum  "$K" - nothing to do"
	fi

	if [ -s $incdir/.compat.patch ]; then
		cat $incdir/.compat.patch >> $compat_patch.tmp
	fi

	if [ -s $compat_patch.tmp ]; then
		mv $compat_patch.tmp $compat_patch
	else
		# hooray, there are no compat patches necessary
		touch $compat_patch
	fi

	# keep it around
	# to better be able to match the "stderr" warnings to their source files
	# rm -f $incdir/.compat.cocci
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
	SPAAS_URL=${SPAAS_URL:-https://spaas.drbd.io}
	if ! curl -fsS "${SPAAS_URL}/api/v1/hello"; then
		echo "  ERROR: SPAAS is not reachable! Please check if your network"
		echo "  configuration or some firewall prohibits access to "
		echo "  '${SPAAS_URL}'."
		exit 1
	fi

	REL_VERSION=$(sed -ne '/^\#define REL_VERSION/{s/^[^"]*"\([^ "]*\).*/\1/;p;q;}' linux/drbd_config.h)
	rm -f $compat_patch.tmp.header $compat_patch.tmp
	if ! base64 $incdir/compat.h |
		curl -T - -X POST -o $compat_patch.tmp -D $compat_patch.tmp.header -f \
		"${SPAAS_URL}/api/v1/spatch/${REL_VERSION}"
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
	echo "  by calling \"echo drbd/$compat_patch >>.filelist ; make tgz\""
fi
