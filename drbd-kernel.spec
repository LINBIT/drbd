Name: drbd-kernel
Summary: Kernel driver for DRBD
Version: 9.0.28
Release: 1

# always require a suitable userland
Requires: drbd-utils >= 9.2.0

%global tarball_version %(echo "%{version}-%{?release}" | sed -e "s,%{?dist}$,,")
Source: http://oss.linbit.com/drbd/drbd-%{tarball_version}.tar.gz
License: GPLv2+
Group: System Environment/Kernel
URL: http://www.drbd.org/
BuildRoot: %(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)
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
# Needed, because even though kABI is still "compatible" in RHEL 6.0 to 6.1,
# the actual functionality differs very much: 6.1 does no longer do BARRIERS,
# but wants FLUSH/FUA instead.
# For convenience, we want both 6.0 and 6.1 in the same repository,
# and have yum/rpm figure out via dependencies, which kmod version should be installed.
# This is a dirty hack, non generic, and should probably be enclosed in some "if-on-rhel6".
%define _this_kmp_version %{version}_%(echo %kernel_version | sed -r 'y/-/_/; s/\.el.\.(x86_64|i.86)$//;')
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
echo "override drbd * weak-updates" \
    > $RPM_BUILD_ROOT/etc/depmod.d/drbd.conf
install -D misc/SECURE-BOOT-KEY-linbit.com.der $RPM_BUILD_ROOT/etc/pki/linbit/SECURE-BOOT-KEY-linbit.com.der
%endif

%clean
rm -rf %{buildroot}

%changelog
* Thu Feb 25 2021 Philipp Reisner <phil@linbit.com> - 9.0.28-1
- New upstream release.

* Wed Dec 23 2020 Lars Ellenberg <lars@linbit.com> - 9.0.27-1
- New upstream release.
- Fix regression: allow live migration between two diskful peers again

* Tue Dec 22 2020 Philipp Reisner <phil@linbit.com> - 9.0.26-1
- New upstream release.

* Tue Sep 22 2020 Philipp Reisner <phil@linbit.com> - 9.0.25-1
- New upstream release.

* Mon Jun 29 2020 Philipp Reisner <phil@linbit.com> - 9.0.24-1
- New upstream release.

* Mon Jun 08 2020 Philipp Reisner <phil@linbit.com> - 9.0.23-1
- New upstream release.

* Mon Mar 30 2020 Philipp Reisner <phil@linbit.com> - 9.0.22-2
- Fix reads on diskless in the presence of IO errors
- Fix diskless nodes leaving a quorum enabled cluster

* Tue Mar 10 2020 Philipp Reisner <phil@linbit.com> - 9.0.22-1
- New upstream release.

* Mon Nov 11 2019 Philipp Reisner <phil@linbit.com> - 9.0.21-1
- New upstream release.

* Thu Oct 10 2019 Philipp Reisner <phil@linbit.com> - 9.0.20-1
- New upstream release.

* Mon Jul 08 2019 Philipp Reisner <phil@linbit.com> - 9.0.19-1
- New upstream release.

* Fri May 31 2019 Lars Ellenberg <lars@linbit.com> - 9.0.18.1-1
- New upstream release.

* Fri May 24 2019 Philipp Reisner <phil@linbit.com> - 9.0.18-1
- New upstream release.

* Tue Mar 26 2019 Philipp Reisner <phil@linbit.com> - 9.0.17-1
- New upstream release.

* Thu Oct 25 2018 Philipp Reisner <phil@linbit.com> - 9.0.16-1
- New upstream release.

* Tue Aug 14 2018 Philipp Reisner <phil@linbit.com> - 9.0.15-1
- New upstream release.

* Tue May 01 2018 Lars Ellenberg <lars@linbit.com> - 9.0.14-1
- New upstream release.

* Tue Apr 17 2018 Philipp Reisner <phil@linbit.com> - 9.0.13-1
- New upstream release.

* Mon Jan 22 2018 Philipp Reisner <phil@linbit.com> - 9.0.12-1
- New upstream release.

* Tue Jan 09 2018 Roland Kammerer <roland.kammerer@linbit.com> - 9.0.11-1
- New upstream release.

* Fri Dec 22 2017 Roland Kammerer <roland.kammerer@linbit.com> - 9.0.10-1
- New upstream release.

* Thu Aug 31 2017 Philipp Reisner <phil@linbit.com> - 9.0.9-1
- New upstream release.

* Mon Jun 19 2017 Philipp Reisner <phil@linbit.com> - 9.0.8-1
- New upstream release.

* Fri Mar 31 2017 Philipp Reisner <phil@linbit.com> - 9.0.7-1
- New upstream release.

* Fri Dec 23 2016 Philipp Reisner <phil@linbit.com> - 9.0.6-1
- New upstream release.

* Thu Oct 20 2016 Philipp Reisner <phil@linbit.com> - 9.0.5-1
- New upstream release.

* Tue Sep 06 2016 Philipp Reisner <phil@linbit.com> - 9.0.4-1
- New upstream release.

* Thu Jul 14 2016 Philipp Reisner <phil@linbit.com> - 9.0.3-1
- New upstream release.

* Tue Apr 19 2016 Philipp Reisner <phil@linbit.com> - 9.0.2-1
- New upstream release.

* Tue Feb 02 2016 Philipp Reisner <phil@linbit.com> - 9.0.1-1
- New upstream release.

* Tue Jul 28 2015 Lars Ellenberg <lars@linbit.com> - 9.0.0-3
- Fixes for the RDMA transport
- Fixes for 8.4 compatibility
- Rebuild after compat and build system fixes

* Tue Jun 16 2015 Philipp Reisner <phil@linbit.com> - 9.0.0-1
- New upstream release.

* Mon Jul 18 2011 Philipp Reisner <phil@linbit.com> - 8.4.0-1
- New upstream release.

* Fri Jan 28 2011 Philipp Reisner <phil@linbit.com> - 8.3.10-1
- New upstream release.

* Thu Nov 25 2010 Andreas Gruenbacher <agruen@linbit.com> - 8.3.9-1
- Convert to a Kernel Module Package.
