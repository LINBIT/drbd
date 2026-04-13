#!/bin/sh

usage() {
	echo "Usage: $(basename "$0") [--skip] <commitish>"
	echo "       $(basename "$0") --status [<branch>]"
	echo ""
	echo "Merge a commit from a maintenance branch into the current branch."
	echo "The source branch (e.g. drbd-9.2) is detected automatically"
	echo "from origin's drbd-* branches."
	echo ""
	echo "Options:"
	echo "  --skip              Use 'ours' strategy (record merge without taking changes)"
	echo "  --status [branch]   Show commits not yet merged into the current branch."
	echo "                      If no branch is given, check all origin drbd-X.Y branches."
	exit 1
}

show_status() {
	if [ -n "$1" ]; then
		branches="$1"
	else
		branches=$(git for-each-ref --format='%(refname:short)' 'refs/remotes/origin/drbd-*' \
			| grep -E '^origin/drbd-[0-9]+\.[0-9]+$')
	fi

	for b in $branches; do
		if ! git rev-parse --verify "$b" >/dev/null 2>&1; then
			echo "Error: branch $b does not exist" >&2
			exit 1
		fi

		count=$(git rev-list --count HEAD.."$b")
		if [ "$count" -eq 0 ]; then
			echo "$b: up to date"
		else
			echo "$b: $count commit(s) pending"
			git log --reverse --format='%h %as %an: %s' HEAD.."$b"
		fi
		echo
	done
	exit 0
}

skip=false
status=false
while [ $# -gt 0 ]; do
	case "$1" in
	--skip)
		skip=true
		shift
		;;
	--status)
		status=true
		shift
		;;
	-*)
		usage
		;;
	*)
		break
		;;
	esac
done

if $status && $skip; then
	echo "Error: --status and --skip are mutually exclusive" >&2
	exit 1
fi

if $status; then
	show_status "$1"
fi

if [ "$#" -ne 1 ]; then
	usage
fi

commitish=$1

# Determine the source branch from origin's drbd-X.Y style branches
branch=$(git name-rev --name-only --refs='refs/remotes/origin/drbd-*.*' "$commitish" \
	| sed 's|~[0-9]*$||; s|\^[0-9]*$||; s|^remotes/||; s|^origin/||')

if ! echo "$branch" | grep -qE '^drbd-[0-9]+\.[0-9]+$'; then
	echo "Error: could not determine source branch for $commitish" >&2
	echo "The commit must be reachable from an origin drbd-X.Y branch." >&2
	exit 1
fi

if [ "$skip" = true ]; then
	action="Skip"
	strategy="--strategy=ours"
else
	action="Merge"
	strategy=""
fi

subject=$(git show -s --format='%s' "$commitish")
# If already a Merge/Skip commit, unwrap the inner subject to avoid nesting
if echo "$subject" | grep -E -q "^(Merge|Skip) "; then
	subject=$(echo "$subject" | sed "s/^[^']*'\\(.*\\)'$/\\1/")
fi
msg=$(git show -s --format="${action} ${branch}/%h" --abbrev=12 "$commitish")
msg="${msg} '${subject}'"
git merge --message "${msg}" --no-edit $strategy "$commitish"
