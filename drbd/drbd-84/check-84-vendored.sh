#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# The v1 ("drbd" family, version 1) netlink serialization is carried
# verbatim from the in-tree DRBD 8.4 driver. Mainline generated it from a
# YNL spec that was deliberately not upstreamed, so there is nothing to
# regenerate here: the files are vendored byte for byte, and this script
# proves they still match their origin.
#
#   KDIR=/path/to/linux drbd-84/check-84-vendored.sh
set -euo pipefail

MAINLINE_COMMIT=8098eeb693c4cc4e774c62fbd4875197cb5578ce
HERE="$(cd "$(dirname "$0")" && pwd)"

: "${KDIR:?set KDIR to a Linux kernel git checkout containing $MAINLINE_COMMIT}"
git -C "$KDIR" cat-file -e "$MAINLINE_COMMIT^{commit}" 2>/dev/null || {
	echo "error: $MAINLINE_COMMIT not found in $KDIR" >&2
	exit 1
}

rc=0
# diff exits 1 for "files differ" and 2 for trouble, such as a local file
# that does not exist; report those two cases with distinct messages instead
# of calling both "drifted".
check() {  # check <mainline path> <local path>
	if ! git -C "$KDIR" show "$MAINLINE_COMMIT:$1" | diff -u - "$HERE/$2"; then
		diff_rc=${PIPESTATUS[1]}
		if [ ! -e "$HERE/$2" ]; then
			echo "error: $2 does not exist locally (expected to match mainline $1)" >&2
		elif [ "$diff_rc" -eq 1 ]; then
			echo "error: $2 has drifted from mainline $1" >&2
		else
			echo "error: failed to compare $2 against mainline $1 (diff exit $diff_rc)" >&2
		fi
		rc=1
	fi
}

check include/uapi/linux/drbd_genl.h    uapi/linux/drbd_genl.h
check drivers/block/drbd/drbd_nl_gen.h  drbd_nl_gen.h
check drivers/block/drbd/drbd_nl_gen.c  drbd_nl_gen.c

[ $rc -eq 0 ] && echo "vendored drbd-8.4 netlink sources match mainline $MAINLINE_COMMIT"
exit $rc
