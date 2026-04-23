#!/bin/bash
# Wrapper around checkpatch.pl for DRBD source.
# Used by CI (.gitlab-ci.yml) and git hooks (misc/pre-commit, misc/commit-msg).

set -eu

# Resolve checkpatch.pl: honour $CHECKPATCH, otherwise search $PATH.
if [ -n "${CHECKPATCH:-}" ]; then
	checkpatch=$CHECKPATCH
else
	checkpatch=$(command -v checkpatch.pl) || {
		echo "checkpatch.pl not found" >&2
		exit 1
	}
fi

mode=${1:-}
shift || true

case "$mode" in
commits)
	# CI: check code + commit messages for a range of commits
	base=${1:?missing base}

	tmpdir=$(mktemp -d)
	trap 'rm -rf "$tmpdir"' EXIT

	i=0
	for rev in $(git rev-list "${base}..HEAD"); do
		diff=$(git diff --submodule=diff "${rev}~1..${rev}" -- \
			drbd/{drbd-headers/{linux/,},linux/,}*\.[ch])
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
	;;

staged)
	# pre-commit: check staged C/H file changes (no commit message yet)
	diff=$(git diff --cached HEAD -- drbd/{drbd-headers/{linux/,},linux/,}*\.[ch])
	if [ -z "$diff" ]; then
		exit 0
	fi

	echo "$diff" | "$checkpatch" --no-tree --ignore FILE_PATH_CHANGES -
	;;

message)
	# commit-msg: check commit message only (code style is checked by
	# the pre-commit hook and CI). A stub diff line triggers checkpatch's
	# patch mode so that Signed-off-by and Fixes tag checks are active.
	msgfile=${1:?missing message file}

	tmpdir=$(mktemp -d)
	trap 'rm -rf "$tmpdir"' EXIT
	patch="$tmpdir/0001-commit-msg.patch"

	# Mirror git's own default --cleanup=strip: drop '#' comments, leading/
	# trailing blank lines, trailing whitespace, and collapse blank runs.
	# This is what git will store in the commit, and it guarantees line 1
	# is the subject, line 2 the separator blank (if there's a body), and
	# line 3+ the body.
	stripped=$(git stripspace --strip-comments < "$msgfile")
	subject=$(echo "$stripped" | head -1)

	# 'fixup' commits are temporary - do not check.
	echo "$subject" | grep -qE '^fixup!' && exit 0

	author=$(git var GIT_AUTHOR_IDENT | sed 's/> .*/>/')

	{
		echo "From: $author"
		echo "Subject: [PATCH] $subject"
		echo
		echo "$stripped" | tail -n +3
		echo "---"
		echo "diff --git a/x b/x"
	} > "$patch"

	# Merge/Skip commits: check message formatting but not
	# Signed-off-by or Fixes tags.
	extra_args=()
	echo "$subject" | grep -qE '^(Merge|Skip)' &&
		extra_args=(--no-signoff --no-fixes-tag)

	"$checkpatch" --no-tree --ignore FILE_PATH_CHANGES "${extra_args[@]}" "$patch"
	;;

*)
	echo "Usage: $0 {commits <base>|staged|message <msg-file>}" >&2
	exit 1
	;;
esac
