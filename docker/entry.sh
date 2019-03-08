#!/bin/bash

die() {
	>&2 echo
	>&2 echo "$1"
	exit 1
}

patch_weak_modules() {
cat <<'EOF' >/sbin/weak-modules
#!/bin/bash

weak_modules() {
	local IFS=$'\n'
	modules=($(cat))

	wmp=/lib/modules/$(uname -r)/weak-updates/drbd
	rm -rf "$wmp"
	mkdir -p "$wmp"
	cd "$wmp"
	for ((n = 0; n < ${#modules[@]}; n++)); do
		ln -s ${modules[$n]} .
	done
}

weak_modules
depmod -a
exit 0
EOF

chmod +x /sbin/weak-modules
}

failed=no
if [ -n "$(type -p dpkg)" ]; then
	dpkg --ignore-depends=drbd-utils \
		-i /pkgs/drbd-module-"$(uname -r)"*.deb || failed=yes
else
	patch_weak_modules
	no_initramfs=1 rpm --nodeps \
		-i /pkgs/kmod-drbd-9*_*"$(uname -r | cut -f2 -d'-' | cut -f1 -d '.')"*.rpm || failed=yes
fi
[[ $failed == no ]] || die "No matching module package found"

modprobe drbd usermode_helper=disabled
modprobe drbd_transport_tcp
modprobe drbd_transport_rdma 2>/dev/null || true
if ! grep -q drbd_transport_tcp /proc/modules; then
        die "Could not load DRBD kernel modules"
fi

echo
echo "DRBD modules successfully loaded"
exit 0
