#!/bin/bash

die() {
	>&2 echo
	>&2 echo "$1"
	exit 1
}

pkgdir=/tmp/pkg
kodir=/tmp/ko
mkdir -p "$pkgdir" "$kodir"

failed=no
if [ -n "$(type -p dpkg)" ]; then
	dpkg -x /pkgs/drbd-module-"$(uname -r)"*.deb "$pkgdir"
else
	find /pkgs -name "kmod-drbd-9*_*""$(uname -r | cut -f2 -d'-' | cut -f1 -d '.')""*.rpm" -exec cp {} "$pkgdir" \;
	cd "$pkgdir" || failed=yes
	rpm2cpio ./*.rpm | cpio -idmv 2>/dev/null
fi

find "$pkgdir"/lib/modules -name "*.ko" -exec cp {} "$kodir" \;
cd "$kodir" || failed=yes

# from here on we expect we are in a CWD that has the kos
if [ ! -f drbd.ko ] || [ ! -f drbd_transport_tcp.ko ]; then
	failed=yes
fi
[[ $failed == no ]] || die "No matching module package found"

# as we insmod, we need to load our dependencies; we assume /lib/modules to be bindmounted
modprobe libcrc32c
insmod ./drbd.ko usermode_helper=disabled
insmod ./drbd_transport_tcp.ko
modprobe drbd_transport_rdma 2>/dev/null || true
if ! grep -q drbd_transport_tcp /proc/modules; then
        die "Could not load DRBD kernel modules"
fi

echo
echo "DRBD modules successfully loaded"
exit 0
