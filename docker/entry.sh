#!/bin/bash

SIGN_KEY=https://packages.linbit.com/package-signing-pubkey.asc

die() {
	>&2 echo
	>&2 echo "$1"
	exit 1
}

map_dist() {
	local k=${1:-doesnotexist}
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

print_version_and_exit() {
	echo
	echo "DRBD version loaded:"
	cat /proc/drbd
	exit 0
}

# ret 0 if repo file exists
#     1 if repo file does not exist but exptected vars are set
#     2 if building from source
# err msg, which should then be used in die()
HOW_REPOFILE=0
HOW_VARS=1
HOW_FROMSRC=2
how_to_load() {
	local repo="$1"

	[ -f "$repo" ] && { echo $HOW_REPOFILE; return; }
	[ -n "$LB_DIST" ] && [ -n "$LB_HASH" ] && { echo $HOW_VARS; return; }
	[ -d "/lib/modules/$(uname -r)" ] && { echo $HOW_FROMSRC; return; }

	echo "You need to set LB_DIST and LB_HASH; or bind mount your existing repo config to $1; or bindmount /lib/modules"
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
	wget -qO - $SIGN_KEY | apt-key add -
}

repo::rpm::createrepo() {
	local dist="$1"
	local hash="$2"

cat << EOF > "$(repo::rpm::getrepofile)"
[drbd-9]
name=DRBD9 - \$basearch
baseurl=http://packages.linbit.com/${hash}/yum/${dist}/drbd-9.0/\$basearch
gpgkey=$SIGN_KEY
gpgcheck=1
enabled=1
EOF
}
repo::deb::createrepo() {
	local dist="$1"
	local hash="$2"

cat << EOF > "$(repo::deb::getrepofile)"
deb http://packages.linbit.com/${hash}/ ${dist} drbd-9.0
EOF
}

kos::fromsrc() {
	local pkgdir="$1"
	local kodir="$2"

	cd "$pkgdir" || die "Could not cd to $pkgdir"
	tar xf /drbd.tar.gz
	# cd $(ls -1 | head -1) || die "Could not cd"
	cd drbd-* || die "Could not cd to drbd src dir"
	make -j
	# mv drbd/*.ko "$kodir"
}

kos::rpm::frompkg() {
	local pkgdir="$1"

	cd "$pkgdir" || die "Could not cd to $pkgdir"
	yumdownloader -y --disablerepo="*" --enablerepo=drbd-9 kmod-drbd
	rpm2cpio ./*.rpm | cpio -idmv 2>/dev/null
}

kos::deb::frompkg() {
	local pkgdir="$1"

	local pkg

	chown _apt "$pkgdir"
	cd "$pkgdir" || die "Could not cd to $pkgdir"
	pkg=drbd-module-"$(uname -r)"
	apt-get update -o Dir::Etc::sourcelist="sources.list.d/linbit.list" \
		-o Dir::Etc::sourceparts="-" \
		-o APT::Get::List-Cleanup="0" && apt-get -y download "$pkg"
	dpkg -x ./"$pkg"*.deb "$pkgdir"
}


### main
grep -q '^drbd' /proc/modules && echo "DRBD module is already loaded" && print_version_and_exit

dist=$(map_dist "$LB_DIST")

pkgdir=/tmp/pkg
kodir=/tmp/ko
rm -rf "$pkgdir" "$kodir"
mkdir -p "$pkgdir" "$kodir"

fmt=rpm
[ -n "$(type -p dpkg)" ] && fmt=deb
repo=$(repo::$fmt::repofile)

how=$(how_to_load "$repo")

case $how in
	$HOW_FROMSRC)
		kos::fromsrc "$pkgdir" "$kodir"
		;;
	$HOW_REPOFILE|$HOW_VARS)
		repo::$fmt::getsignkey
		[[ $how == "$HOW_VARS" ]] && repo::$fmt::createrepo "$dist" "$LB_HASH"
		kos::$fmt::frompkg "$pkgdir"
		;;
	*) die "$how" ;;
esac

find "$pkgdir" -name "*.ko" -exec cp {} "$kodir" \;
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

