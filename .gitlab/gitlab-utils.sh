# Helper functions for CI

# Replace the drbd version number in all necessary places
drbd_dummy_release() {
	local version="$1"
	local release="$2"

	dummy-release.sh drbd "$version" "$release" drbd-kernel.spec

	sed -re "s/(#define REL_VERSION) .*/\1 \"${version}-${release}\"/g" drbd/linux/drbd_config.h > drbd/linux/drbd_config.h.tmp
	mv drbd/linux/drbd_config.h{.tmp,}

	for i in 7 8; do
		sed -re "s/(ENV DRBD_VERSION) .*/\1 ${version}-${release}/g" docker/Dockerfile.centos${i} > docker/Dockerfile.centos${i}.tmp
		mv docker/Dockerfile.centos${i}{.tmp,}
	done

	cat > ChangeLog << EOF
${version}-${release} (api:genl2/proto:86-117/transport:14)
--------

  * Dummy release
EOF
}
