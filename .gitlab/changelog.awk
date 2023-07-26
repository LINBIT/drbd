# Can be used to add a release to the ChangeLog
#
# Example:
# awk -f changelog.awk -v REL_VERSION=9.9.9 ChangeLog > ChangeLog.ci

BEGIN {
	if (REL_VERSION == "")
		die("REL_VERSION is not set")
}

!added && /api:/ {
	print REL_VERSION " " $2
	print "--------"
	print ""
	print " * bug fixes"
	print ""
	added = 1
}

{print}

function die(msg) {
	print(msg) > "/dev/stderr"
	exit 1
}
