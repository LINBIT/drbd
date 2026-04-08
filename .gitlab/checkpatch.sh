#!/bin/bash
# Build a synthetic patch per commit: format-patch header (for commit
# message checking) combined with git-diff (for --submodule=diff and path filtering).

set -eu

base=$1
checkpatch=$2

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

i=0
for rev in $(git rev-list ${base}..HEAD); do
	diff=$(git diff --submodule=diff ${rev}~1..${rev} -- drbd/{drbd-headers/{linux/,},linux/,}*\.[ch])
	if [ -n "$diff" ]; then
		slug=$(git log -1 --format='%f' "$rev")
		patch="$tmpdir/$(printf '%04d' $i)-${slug}.patch"
		git format-patch --stdout -1 "$rev" | sed '/^---$/q' > "$patch"
		echo "$diff" >> "$patch"
		i=$((i + 1))
	fi
done

if [ $i -eq 0 ]; then
	echo "No relevant patches found."
	exit 0
fi

"$checkpatch" --no-tree --ignore FILE_PATH_CHANGES "$tmpdir"/*.patch
