#!/bin/bash

SIGN_KEY=https://packages.linbit.com/package-signing-pubkey.asc
PKGS=/pkgs
HOSTRELEASE=/etc/host-release

die() {
	>&2 echo
	>&2 echo -e "$1"
	exit 1
}

debug() {
	[ -n "$LB_DEBUG" ] || return 0

	>&2 echo
	>&2 echo "DEBUG: $1"
	>&2 echo
}

map_dist() {
	# allow to override
	[ -n "$LB_DIST" ] && { echo "$LB_DIST"; return 0; }

	# if we got called, and are that far we can assume this mapped file has to exist
	[ -f "$HOSTRELEASE" ] || die "You have to bind-mount /etc/os-release to the container's $HOSTRELEASE"
	lbdisttool.py --os-release $HOSTRELEASE -l || echo ""

	return 0
}

host_dist_matches_image_dist() {
	host_dist="$( map_dist | cut -d'.' -f1 )"
	if [[ -z "$host_dist" ]] ; then
		debug "Cannot get host distro!"
		return 1
	fi

	image_dist="$( lbdisttool.py -l | cut -d'.' -f1 )"
	if [[ "$host_dist" == "$image_dist" ]]; then
		debug "The host distro matches image distro!"
		return 0
	else
		debug "The host distro does not match image distro"
		return 1
	fi
}

print_drbd_version() {
	echo
	echo "DRBD version loaded:"
	cat /proc/drbd
}

print_drbd_version_and_exit() {
	print_drbd_version
	exit 0
}

drbd_matches_min_version() {
	[ -z "$1" ] && return 0

	sort -C -V <(cat - /sys/module/drbd/version <<<"$1")
}

HOW_DEPSONLY=deps_only

HOW_REPOFILE=repo_file; HOW_HASH=node_hash; HOW_FROMSRC=compile; HOW_FROMSHIPPED=shipped_modules
how_to_get() {
	local repo="$1"
	local how=""

	if [ -n "$LB_HOW" ]; then # allow to override
		how="$LB_HOW"
	elif [ -f "$repo" ]; then
		how=$HOW_REPOFILE
	elif [ -n "$LB_HASH" ]; then
		how=$HOW_HASH
	elif mountpoint -q /usr/src; then
		how=$HOW_FROMSRC
	else
		how=$HOW_FROMSHIPPED
	fi

	echo "$how"
	return 0
}

needs_dist() {
	local how="$1"
	local needsdist=n
	if [[ $how == "$HOW_HASH" ]]; then
		needsdist=y
	fi

	echo "$needsdist"
	return 0
}

HOW_LOAD_FROM_RAM=RAM  # insmod
HOW_INSTALL=install  # make install && modprobe
how_to_load() {
	[[ $LB_INSTALL == yes ]] && echo "$HOW_INSTALL" || echo "$HOW_LOAD_FROM_RAM"

	return 0
}

repo::rpm::getrepofile() {
	echo /etc/yum.repos.d/linbit.repo
}
repo::deb::getrepofile() {
	echo /etc/apt/sources.list.d/linbit.list
}

repo::rpm::getsignkey() {
	rpm --import $SIGN_KEY
}
repo::deb::getsignkey() {
	curl -fsSL $SIGN_KEY | gpg -o /etc/apt/trusted.gpg.d/linbit-keyring.gpg --dearmor -
}

repo::rpm::createrepo() {
	local dist="$1"
	local hash="$2"

cat << EOF > "$(repo::rpm::getrepofile)"
[drbd-9]
name=DRBD9 - \$basearch
baseurl=http://packages.linbit.com/${hash}/yum/${dist}/drbd-9/\$basearch
gpgkey=$SIGN_KEY
gpgcheck=1
enabled=1
EOF
}
repo::deb::createrepo() {
	local dist="$1"
	local hash="$2"

cat << EOF > "$(repo::deb::getrepofile)"
deb [signed-by=/etc/apt/trusted.gpg.d/linbit-keyring.gpg] http://packages.linbit.com/${hash}/ ${dist} drbd-9
EOF
}

kos::fromsrc() {
	local pkgdir="$1"
	local kodir="$2"

	cd "$pkgdir" || die "Could not cd to $pkgdir"
	tar xf /drbd.tar.gz
	# cd $(ls -1 | head -1) || die "Could not cd"
	cd drbd-* || die "Could not cd to drbd src dir"
	make $LB_MAKEOPTS
}

kos::rpm::extract() {
	local pkgdir="$1"
	cd "$pkgdir" || die "Could not cd to $pkgdir"
	rpm2cpio ./*.rpm | cpio -idmv 2>/dev/null
}
kos::deb::extract() {
	local pkgdir="$1"
	cd "$pkgdir" || die "Could not cd to $pkgdir"
	dpkg -x ./*.deb "$pkgdir"
}

kos::rpm::fromrepo() {
	local pkgdir="$1"

	cd "$pkgdir" || die "Could not cd to $pkgdir"
	yumdownloader -y --disablerepo="*" --enablerepo=drbd-9 kmod-drbd || yum download -y --disablerepo="*" --enablerepo=drbd-9 kmod-drbd
	kos::rpm::extract "$pkgdir"
}
kos::deb::fromrepo() {
	local pkgdir="$1"
	local pkg

	chown _apt "$pkgdir"
	cd "$pkgdir" || die "Could not cd to $pkgdir"
	pkg=drbd-module-"$(uname -r)"
	apt-get update -o Dir::Etc::sourcelist="sources.list.d/linbit.list" \
		-o Dir::Etc::sourceparts="-" \
		-o APT::Get::List-Cleanup="0" && apt-get -y download "$pkg"
	kos::deb::extract "$pkgdir"
}

kos::rpm::bestbyrpmprovides() {
	local pkgdir="$1"
	local kernel_provides_file="$pkgdir/kernel.provides"
	local drbd_requires_file
	shift 1

	sort > "$kernel_provides_file" \
		<(find "/lib/modules/$(uname -r)" -name "symvers*" | /lib/rpm/kabi.sh) \
		<(find "/lib/modules/$(uname -r)/kernel" -type f | /lib/rpm/redhat/find-provides.ksyms)

	if [ ! -s "$kernel_provides_file" ]; then
		debug "Failed to generate kernel provides"
		return 1
	fi

	for RPM in "$@"; do
		drbd_requires_file="$pkgdir/$(basename "$RPM").requires"
		rpm -q -R -p "$RPM" | grep ^kernel > "$drbd_requires_file"

		if [ ! -s "$drbd_requires_file" ]; then
			debug "Failed to parse drbd kernel requirements for $RPM"
			continue
		fi

		if [ -z "$(comm -13 "$kernel_provides_file" "$drbd_requires_file")" ]; then
			debug "Kernel module matching kernel provides: \"$RPM\""
			echo "$RPM"
			return 0
		fi
	done

	debug "No kernel module matches kernel provides"

	return 1
}

kos::rpm::fromshipped() {
	local pkgdir="$1"
	local family
	local best

	family="$(lbdisttool.py --family)"

	best="$(kos::rpm::bestbyrpmprovides "$pkgdir" "${PKGS}/${family}"*/*.rpm || lbdisttool.py --force-name "$family" -k "${PKGS}/${family}"*/*.rpm)"
	[ -n "$best" ] || die "Could not find matching rpm package for your kernel"
	debug "Best kernel module package: \"$best\""
	cp "$best" "$pkgdir"

	kos::rpm::extract "$pkgdir"
}
kos::deb::fromshipped() {
	local pkgdir="$1"

	cp "$PKGS"/*/"drbd-module-$(uname -r)_"*.deb "$pkgdir"
	nr_debs=$(find "$pkgdir" -name "*.deb" | wc -l)
	[[ $nr_debs -eq 1 ]] || die "Expected to find 1 matching package, but got: $nr_debs"

	kos::deb::extract "$pkgdir"
}

load_from_ram() {
	local pkgdir="$1"
	local kodir="$2"

	find "$pkgdir" -name "*.ko" -exec cp {} "$kodir" \;
	cd "$kodir" || die "Could not cd to $kodir"
	if [ ! -f drbd.ko ] || [ ! -f drbd_transport_tcp.ko ]; then
		die "Could not find the expexted *.ko, see stderr for more details"
	fi

	if [ -d "$LB_SIGN" ]; then
		# guess we could source the whole thing, but...
		eval "$(grep CONFIG_MODULE_SIG_HASH= "/lib/modules/$(uname -r)/build/.config")"
		find . -name "*.ko" -print0 | xargs -0 -n1 "/lib/modules/$(uname -r)/build/scripts/sign-file" "$CONFIG_MODULE_SIG_HASH" "${LB_SIGN}/signing_key.pem" "${LB_SIGN}/signing_key.x509" 
	fi

	if [ -n "$LB_SELINUX_AS" ]; then
		for m in drbd.ko drbd_transport_tcp.ko drbd_transport_rdma.ko; do
			chcon -t "$LB_SELINUX_AS" ./${m} || true
		done
	fi

	insmod ./drbd.ko usermode_helper=disabled
	insmod ./drbd_transport_tcp.ko
	insmod ./drbd_transport_rdma.ko 2>/dev/null || true
}

modprobe_deps() {
	# we are not too strict about these, not all are required everywhere
	#
	# libcrc32c: dependency for DRBD
	# lru_cache: dependency for DRBD (starting with 9.1.13/9.2.2; built in for RHEL9)
	# nvmet_rdma, nvme_rdma: LINSTOR NVME layer
	# loop: LINSTOR when using loop devices as backing disks
	# dm_writecache: LINSTOR writecache layer
	# dm_cache: LINSTOR cache layer
	# dm_thin_pool: LINSTOR thinly provisioned storage
	# dm_snapshot: LINSTOR snapshotting
	# dm_crypt: LINSTOR encrypted volumes

	local s;
	for m in libcrc32c lru_cache nvmet_rdma nvme_rdma loop dm_writecache dm_cache dm_thin_pool dm_snapshot dm_crypt; do
		modprobe "$m" 2>/dev/null && s=success || s=failed
		debug "Loading ${m}: ${s}"
	done

	return 0
}

### main
# LB_SKIP
# allows skipping (or failing) if the linux distro of the host does not match that of this image
# Allow "exit 0", so that when used as an initContainer in Kubernetes,
# next initContainer with a different distro will be tried
if [[ $LB_SKIP == yes ]]; then
	host_dist_matches_image_dist || exit 0
elif [[ $LB_SKIP == no ]]; then
	host_dist_matches_image_dist || exit 1
fi

modprobe_deps
[[ $LB_HOW == "$HOW_DEPSONLY" ]] && { debug "dependencies loading only, exiting now"; exit 0; }

if grep -q '^drbd ' /proc/modules; then
	echo "DRBD module is already loaded"
	print_drbd_version

	[[ $LB_FAIL_IF_USERMODE_HELPER_NOT_DISABLED == yes ]] && ! grep -qw disabled /sys/module/drbd/parameters/usermode_helper &&
		die "- load the drbd module on the host with the module parameter 'usermode_helper=disabled' OR\n- let this container handle that for you by not already loading the drbd module on the host"

	drbd_matches_min_version "$LB_DRBD_MIN_LOADED_VERSION" ||
		die "DRBD kernel module version loaded does not satisfy the minimum version requirements ('$LB_DRBD_MIN_LOADED_VERSION')"

	exit 0
fi

pkgdir=/tmp/pkg
kodir=/tmp/ko
rm -rf "$pkgdir" "$kodir"
mkdir -p "$pkgdir" "$kodir"

fmt=rpm
if [ -n "$(type -p dpkg)" ]; then
	fmt=deb
elif [ -n "$(type -p emerge)" ]; then
	fmt=emerge
fi

case $fmt in
	rpm|deb)
		repo=$(repo::$fmt::getrepofile)
		how_get=$(how_to_get "$repo") || exit 1
		;;
	emerge)
		# Cannot easily use how_to_get(), as we usually have /usr/src bind-mounted in that case.
		# On flatcar this does not exist and we strictly only support building from source there anyway.
		how_get=$HOW_FROMSRC
		;;
esac

debug "Detected kmod method: \"$how_get\""

dist=we_do_not_care
need_dist=$(needs_dist "$how_get")
debug "Needs host distribution info: \"$need_dist\""
if [[ $need_dist == y ]]; then
	dist=$(map_dist "$LB_DIST") || exit 1
	debug "Detected distribution: \"$dist\""
fi

case $how_get in
	"$HOW_FROMSRC")
		kos::fromsrc "$pkgdir" "$kodir"
		;;
	"$HOW_REPOFILE"|"$HOW_HASH")
		repo::$fmt::getsignkey
		[[ $how_get == "$HOW_HASH" ]] && repo::$fmt::createrepo "$dist" "$LB_HASH"
		kos::$fmt::fromrepo "$pkgdir"
		;;
	"$HOW_FROMSHIPPED")
		kos::$fmt::fromshipped "$pkgdir"
		;;
	*) die "$how_get" ;;
esac

how_load=$(how_to_load) || exit 1
debug "Detected load method: \"$how_load\""
if [[ $how_get == "$HOW_FROMSRC" ]] && [[ $how_load == "$HOW_INSTALL" ]]; then
	cd "$pkgdir" || die "Could not cd to $pkgdir"
	cd drbd-* || die "Could not cd to drbd src dir"
	make install
	modprobe drbd usermode_helper=disabled
	modprobe drbd_transport_tcp
	modprobe drbd_transport_rdma 2>/dev/null || true
else
	load_from_ram "$pkgdir" "$kodir"
fi

grep -q '^drbd_transport_tcp' /proc/modules || die "Could not load DRBD kernel modules"
print_drbd_version_and_exit
