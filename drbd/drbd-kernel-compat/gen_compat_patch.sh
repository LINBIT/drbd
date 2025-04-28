#!/bin/bash

# actually, the 1.1 in fedora 40 seems to have the relevant patches backported.
SUGGESTED_SPATCH_VERSION=1.2
[[ ${V:-0} != [02] ]] && set -x

# to be passed in via environment
: ${sources[@]?}
: ${compat_patch?}
: ${chksum?}

# generate compat patches by using the cache,
# or using spatch,
# or using curl to fetch it from spatch-as-a-service

[[ $compat_patch = drbd-kernel-compat/cocci_cache/*/compat.patch ]] || exit 1

set -e

# compat with older checkouts
if test -e .compat_patches_applied; then
	echo "Removing compat patches"
	patch -R -p0 --batch --reject-file=- < .compat_patches_applied
	rm -f .compat_patches_applied
fi

# Because we are running under "set -e" aka "errexit",
# this must not be called as a condition command inside an "if" or similar,
# short-circuit returns are "return 0",
# and the state propagation happens via variables:
gcc_success=false
need_spatch=false
tried_spatch=false
spatch_success=false
compat_patch_generated=false
try_spatch()
{

	K=$(cat $incdir/kernelrelease.txt || echo unknown kernel release)
	echo "  GENPATCHNAMES   "$K
	gcc -I $incdir -o $incdir/gen_patch_names -std=c99 drbd-kernel-compat/gen_patch_names.c
	gcc_success=true
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
		need_spatch=true
		if ! hash spatch >&/dev/null ; then
			echo "    No local spatch found."
			return 0
		fi
		echo "  COCCISYN  $chksum  "$K
		if ! spatch --very-quiet --parse-cocci "$incdir/.compat.cocci" >/dev/null 2>&1 ; then
			echo "    Local spatch found, but cannot parse our .cocci rules."
			return 0
		fi
		tried_spatch=true
		echo "  SPATCH  $chksum  "$K
		set +e
		# sources=( ... ) passed in via environment
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
		set -e
		[[ $ex != 0 ]] && return 0
		spatch_success=true
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
	compat_patch_generated=true
	return 0
}

try_spatch
if $compat_patch_generated ; then
	: local spatch run successful or not necessary.
else
	if $spatch_success; then
		echo "  Local spatch run was successful, but we still had problems generating the final compat patch; see above."
	elif $need_spatch; then
		if $tried_spatch; then
			echo "  Local spatch run failed; see above."
		else
			echo "  No (suitable) spatch found in \$PATH."
		fi
	elif $gcc_success; then
		echo "  Problem generating the compat patch locally."
	else
		echo "  Problem translating compat.h to the list of necessary patches."
		echo "  We expect a standard build environment, including gcc and glibc-headers|libc-dev."
	fi
	# but still try spatch-as-a-service, maybe?
		
	if test -e ../.git; then
		echo "  INFO: not trying spatch-as-a-service because you are trying"
		echo "  to build DRBD from a git checkout. Please install a suitable"
		echo "  version of coccinelle (>$SUGGESTED_SPATCH_VERSION) or try building from a"
		echo "  release tarball."
		exit 1
	fi

	if [[ $SPAAS != true ]]; then
		echo "  INFO: spatch-as-a-service was disabled by your package"
		echo "  maintainer (\$SPAAS = false). Install a suitable version"
		echo "  of coccinelle (>$SUGGESTED_SPATCH_VERSION) or allow spatch-as-a-service by"
		echo "  setting \$SPAAS = true"
		exit 1
	fi

	echo "  INFO: spatch failed, or no suitable spatch found; trying spatch-as-a-service;"
	echo "  be patient, may take up to 10 minutes."
	echo "  If it is in the server side cache it might only take a second."
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
fi

# still here?
echo "  You can create a new .tgz including this pre-computed compat patch"
echo "  by calling \"echo drbd/$compat_patch >>.filelist ; make tgz\""
