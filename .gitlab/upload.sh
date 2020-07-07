#! /bin/sh

die() {
	echo "$@" 1>&2
	exit 1
}

upload() {
	f=$1
	name=$(basename "$f")
	case $TYPE in
	yum)
		curl -isS \
			-u "$LINBIT_REGISTRY_USER:$LINBIT_REGISTRY_PASSWORD" \
			--upload-file "$f" \
			"$TARGET_REPO/$name"
		;;
	apt)
		curl -isS \
			-u "$LINBIT_REGISTRY_USER:$LINBIT_REGISTRY_PASSWORD" \
			-H "Content-Type: multipart/form-data" \
			--data-binary "@$f" \
			"$TARGET_REPO/"

		;;
	esac
}

[ -z "$LINBIT_REGISTRY_USER" ] && die "LINBIT_REGISTRY_USER not provided"
[ -z "$LINBIT_REGISTRY_PASSWORD" ] && die "LINBIT_REGISTRY_PASSWORD not provided"
[ -z "$TARGET_REPO" ] && die "TARGET_REPO not provided"
[ -z "$TYPE" ] && die "TYPE not provided"

for f in $@; do
	upload "$f"
done
