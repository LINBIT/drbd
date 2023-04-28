# Helper functions for CI

# Replace the drbd version number in all necessary places
drbd_dummy_release() {
	local version="$1"
	local release="$2"
	local rel_version="$3"

	dummy-release.sh drbd "$version" "$release" drbd-kernel.spec

	sed -re "s/(#define REL_VERSION) .*/\1 \"$rel_version\"/g" drbd/linux/drbd_config.h > drbd/linux/drbd_config.h.tmp
	mv drbd/linux/drbd_config.h{.tmp,}

	for i in 7 8 9; do
		sed -re "s/(ENV DRBD_VERSION) .*/\1 $rel_version/g" docker/Dockerfile.rhel${i} > docker/Dockerfile.rhel${i}.tmp
		mv docker/Dockerfile.rhel${i}{.tmp,}
	done

	cat > ChangeLog << EOF
$rel_version (api:genl2/proto:86-117/transport:14)
--------

  * Dummy release
EOF
}
