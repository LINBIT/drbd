# Helper functions for CI

# Prepare directories:
# * download - expected to be cached
# * bin - executables on path
# Also fetch rq
drbd_prepare_tools() {
	mkdir -p download bin
	PATH="$(readlink -f bin):$PATH"

	[ -e download/rq ] || curl -sSfL https://github.com/dflemstr/rq/releases/download/v1.0.2/rq-v1.0.2-x86_64-unknown-linux-gnu.tar.gz | tar -C download -xvzf -
	ln -s ../download/rq bin/rq
}

# Fetch a binary and cache it
drbd_fetch_binary() {
	local name="$1"
	local key="$2"
	local url="$3"
	[ -e download/"$key" ] || { curl -sSfL "$url" > download/"$key" && chmod +x download/"$key" ; }
	ln -s ../download/"$key" bin/"$name"
}

# Fetch lbbuildctl; do not cache it because we always want the latest version
drbd_fetch_lbbuildctl() {
	curl -sSL $LINBIT_REGISTRY_URL/repository/lbbuild/lbbuildctl-latest -o bin/lbbuildctl
	chmod +x bin/lbbuildctl
}

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
