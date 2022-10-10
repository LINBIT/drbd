Name: drbd-kernel
Summary: Kernel driver for DRBD
Version: 9.2.0
Release: 1

# always require a suitable userland
Requires: drbd-utils >= 9.2.0

%global tarball_version %(echo "%{version}" | sed -e "s,%{?dist}$,," -e "s,~,-,")
Source: http://oss.linbit.com/drbd/drbd-%{tarball_version}.tar.gz
Source1: filelist-redhat
Source2: filelist-suse
License: GPLv2+
Group: System Environment/Kernel
URL: http://www.drbd.org/
BuildRoot: %(mktemp -ud %{_tmppath}/%{name}-%{version}-XXXXXX)
%if ! %{defined suse_version}
BuildRequires: redhat-rpm-config
%endif
%if %{defined kernel_module_package_buildreqs}
BuildRequires: %kernel_module_package_buildreqs
%endif

%description
This module is the kernel-dependent driver for DRBD.  This is split out so
that multiple kernel driver versions can be installed, one for each
installed kernel.

%prep
%setup -q -n drbd-%{tarball_version}

%if %{defined suse_kernel_module_package}
# Support also sles10, where kernel_module_package was not yet defined.
# In sles11, suse_k_m_p became a wrapper around k_m_p.

%if 0%{?suse_version} < 1110
# We need to exclude some flavours on sles10 etc,
# or we hit an rpm internal buffer limit.
%suse_kernel_module_package -n drbd -f filelist-suse kdump kdumppae vmi vmipae um
%else
%suse_kernel_module_package -n drbd -f filelist-suse
%endif
%else
# Concept stolen from sles kernel-module-subpackage:
# include the kernel version in the package version,
# so we can have more than one kmod-drbd.
#
# As stated in the RHEL 9 release documents: There is no kernel Application
# Binary Interface (ABI) guarantee between minor releases of RHEL 9.
# So we need to build distinct kernel module packages for each minor release.
# In fact, we have been doing this since RHEL 6, because there have been
# incompatibilities.
#
# For instance, even though the kABI is still "compatible" in RHEL 6.0 to 6.1,
# the actual functionality differs very much: 6.1 does no longer do BARRIERS,
# but wants FLUSH/FUA instead.

# Unfortunately, for us to be able to reference "kernel_version" here,
# it needs to be defined on the command line already.
# If not, it will only be defined within the expansion of "kernel_module_package",
# and only after the "-v" argument was assigned/evaluated...
# duplicate the "latest_kernel" hack from /usr/lib/rpm/macros.d/macros.kmp
%define _this_latest_kernel_devel %({ rpm -q --qf '%%{VERSION}-%%{RELEASE}.%%{ARCH}\\n' `rpm -qa | egrep "^kernel(-rt|-aarch64)?-devel" | /usr/lib/rpm/redhat/rpmsort -r | head -n 1`; echo '%%{nil}'; } | head -n 1)
%if 0%{!?kernel_version:1}
%global kernel_version %_this_latest_kernel_devel
%{warn: "XXX selected %kernel_version based on installed kernel-*-devel packages"}
%endif
%define _this_kmp_version %{version}_%(echo %{kernel_version} | sed -r 'y/-/_/; s/\.el[0-9_]+\.%{_arch}$//;')
%kernel_module_package -v %_this_kmp_version -n drbd -f filelist-redhat %{?lb_flavors}
%endif

%build
rm -rf obj
mkdir obj

for flavor in %flavors_to_build; do
    cp -a -r drbd obj/$flavor
    #make -C %{kernel_source $flavor} M=$PWD/obj/$flavor
    # Workaround: for the whole kernel compatibility patching concept to work,
    # we need to be able to refer to the drbd sources as "drbd". We cannot
    # change the target filenames of the patches, because they are pre-computed
    # and shipped with the release tarball.
    # As a "solution", create a symlink called "drbd" that points to the set of
    # sources that are currently being built.
    # Since we potentially have to build for multiple flavors, remove the link
    # after each build and re-create it for the next one.
    # Since we are using spatch and shipping pre-computed patches, make sure
    # the timestamps are preserved by the cp
    ln -s $flavor obj/drbd
    make -C obj/$flavor %{_smp_mflags} all KDIR=%{kernel_source $flavor}
    rm obj/drbd
done

%install
export INSTALL_MOD_PATH=$RPM_BUILD_ROOT

%if %{defined kernel_module_package_moddir}
export INSTALL_MOD_DIR=%{kernel_module_package_moddir drbd}
%else
%if %{defined suse_kernel_module_package}
export INSTALL_MOD_DIR=updates
%else
export INSTALL_MOD_DIR=extra/drbd
%endif
%endif

# Very likely kernel_module_package_moddir did ignore the parameter,
# so we just append it here. The weak-modules magic expects that location.
[ $INSTALL_MOD_DIR = extra ] && INSTALL_MOD_DIR=extra/drbd

for flavor in %flavors_to_build ; do
    make -C %{kernel_source $flavor} modules_install \
	M=$PWD/obj/$flavor
    kernelrelease=$(cat %{kernel_source $flavor}/include/config/kernel.release || make -s -C %{kernel_source $flavor} kernelrelease)
    mv obj/$flavor/.kernel.config.gz obj/k-config-$kernelrelease.gz
    mv obj/$flavor/Module.symvers ../../RPMS/Module.symvers.$kernelrelease.$flavor.%{_arch}
done

%if %{defined suse_kernel_module_package}
# On SUSE, putting the modules into the default path determined by
# %kernel_module_package_moddir is enough to give them priority over
# shipped modules.
rm -f drbd.conf
%else
mkdir -p $RPM_BUILD_ROOT/etc/depmod.d
printf "override %s * weak-updates/drbd\n" drbd drbd_transport_tcp drbd_transport_rdma\
    > $RPM_BUILD_ROOT/etc/depmod.d/drbd.conf
install -D misc/SECURE-BOOT-KEY-linbit.com.der $RPM_BUILD_ROOT/etc/pki/linbit/SECURE-BOOT-KEY-linbit.com.der
%endif

%clean
rm -rf %{buildroot}

%changelog
* Mon Oct 10 2022 Philipp Reisner <phil@linbit.com> - 9.2.0
-  New upstream release.

* Wed Sep 28 2022 Philipp Reisner <phil@linbit.com> - 9.2.0~rc.8
-  New upstream release.

* Tue Aug 30 2022 Philipp Reisner <phil@linbit.com> - 9.2.0~rc.7
-  New upstream release.

* Wed Jul  6 2022 Philipp Reisner <phil@linbit.com> - 9.2.0~rc.6
-  New upstream release.

* Mon Feb 14 2022 Philipp Reisner <phil@linbit.com> - 9.2.0~rc.4
-  New upstream release.

* Tue Dec 20 2021 Philipp Reisner <phil@linbit.com> - 9.2.0~rc.3
-  New upstream release.

* Tue Dec 14 2021 Philipp Reisner <phil@linbit.com> - 9.2.0~rc.2
-  New upstream release.
