#! /bin/sh

[ ! -d drbd/drbd-kernel-compat ] && echo "Must be called from repository root" && exit 1

for f in drbd/drbd-kernel-compat/tests/*.c; do
	define="COMPAT_$(basename -s .c $f | tr a-z A-Z)"
	used=$(git grep --recurse-submodules "$define" | wc -l)
	[ "$used" -eq "0" ] && echo "$f"
done
