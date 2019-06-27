#!/bin/bash

die() {
	>&2 echo
	>&2 echo "$1"
	exit 1
}

map_dist() {
	local k=$1
	[ -z "$k" ] && k=undef
	k=${k,,}
	k="${k/centos/rhel}"

	declare -A dmap
	# convenience
	dmap["openshift4.1"]="rhel8.0"

	# /etc/os-release ones (${ID}${VERSION_ID})
	dmap["rhcos4.1"]="rhel8.0"
	dmap["ubuntu18.04"]="bionic"

	v=${dmap[$k]}
	[ -n "$v" ] && echo "$v" || echo "$k"
}

signing_key() {
	local key=https://packages.linbit.com/package-signing-pubkey.asc
	case "$1" in
		rpm) rpm --import $key ;;
		deb) wget -qO - $key | apt-key add - ;;
		*) die "Unknown package format ($1)"
	esac
}

# ret 0 if repo file exists
#     1 if repo file does not exist but exptected vars are set
# die() otherwise
repo_or_vars_or_die() {
	local repo="$1"
	[ -f "$repo" ] && return 0;
	[ -n "$LB_DIST" ] && [ -n "$LB_HASH" ] && return 1;
	die "You need to set LB_DIST and LB_HASH; or bind mount your existing repo config to $1"
}

rpm_repo() {
	local dist="$1"
	local hash="$2"
	local repo=/etc/yum.repos.d/linbit.repo

	# always
	signing_key "rpm"

	repo_or_vars_or_die "$repo" && return

cat << EOF > $repo
[drbd-9]
name=DRBD9 - \$basearch
baseurl=http://packages.linbit.com/${hash}/yum/${dist}/drbd-9.0/\$basearch
gpgkey=$GPG_KEY
gpgcheck=1
enabled=1
EOF
}

deb_repo() {
	local dist="$1"
	local hash="$2"
	local repo=/etc/apt/sources.list.d/linbit.list

	# always
	signing_key "deb"

	repo_or_vars_or_die "$repo" && return

cat << EOF > $repo
deb http://packages.linbit.com/${hash}/ ${dist} drbd-9.0
EOF
}

print_version_and_exit() {
	echo
	echo "DRBD version loaded:"
	cat /proc/drbd
	exit 0
}

### main
grep -q '^drbd' /proc/modules && echo "DRBD module is already loaded" && print_version_and_exit

dist=$(map_dist "$LB_DIST")

pkgdir=/tmp/pkg
kodir=/tmp/ko
mkdir -p "$pkgdir" "$kodir"

if [ -n "$(type -p dpkg)" ]; then
	deb_repo "$dist" "$LB_HASH"
	chown _apt "$pkgdir"
	cd "$pkgdir" || die "Could not cd to $pkgdir"
	pkg=drbd-module-"$(uname -r)"
	apt-get update -y && apt-get -y download "$pkg"
	dpkg -x ./"$pkg"*.deb "$pkgdir"
else
	rpm_repo "$dist" "$LB_HASH"
	cd "$pkgdir" || die "Could not cd to $pkgdir"
	yumdownloader -y --disablerepo="*" --enablerepo=drbd-9 kmod-drbd
	rpm2cpio ./*.rpm | cpio -idmv 2>/dev/null
fi

find "$pkgdir"/lib/modules -name "*.ko" -exec cp {} "$kodir" \;
cd "$kodir" || die "Could not cd to $kodir"
if [ ! -f drbd.ko ] || [ ! -f drbd_transport_tcp.ko ]; then
	die "Could not find the expexted *.ko, see stderr for more details"
fi

# as we insmod, we need to load our dependencies; we assume /lib/modules to be bindmounted
modprobe libcrc32c
insmod ./drbd.ko usermode_helper=disabled
insmod ./drbd_transport_tcp.ko
modprobe drbd_transport_rdma 2>/dev/null || true
if ! grep -q '^drbd_transport_tcp' /proc/modules; then
	die "Could not load DRBD kernel modules"
fi
print_version_and_exit

