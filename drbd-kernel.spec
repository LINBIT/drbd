Name: drbd-kernel
Summary: Kernel driver for DRBD
Version: 9.2.10
Release: 1

# always require a suitable userland
Requires: drbd-utils >= 9.27.0

%global tarball_version %(echo "%{version}" | sed -e "s,%{?dist}$,," -e "s,~,-,")
Source: http://oss.linbit.com/drbd/drbd-%{tarball_version}.tar.gz

License: GPLv2+
Group: System Environment/Kernel
URL: http://www.drbd.org/
BuildRoot: %(mktemp -ud %{_tmppath}/%{name}-%{version}-XXXXXX)

BuildRequires: diffutils
BuildRequires: patch
BuildRequires: /usr/bin/perl
%if ! %{defined suse_version}
BuildRequires: redhat-rpm-config
%endif
%if %{defined kernel_module_package_buildreqs}
BuildRequires: %kernel_module_package_buildreqs
%endif

# rpmbuild --with gcov to set GCOV_PROFILE=y for make
%bcond_with gcov

# rpmbuild --define "ofed_kernel_dir /usr/src/ofa_kernel/x86_64/4.18.0-147.5.1..."
# to build against an some mlnx-ofa_kernel-devel
%if %{defined ofed_kernel_dir}
%global _ofed_version %(rpm -qf --qf '%%{VERSION}_%%{RELEASE}' '%{ofed_kernel_dir}')
%if "%_ofed_version" == ""
%{error:ofed_kernel_dir should belong to an rpm package}}
%endif
%global _ofed_version_nodash .ofed.%(echo %{?_ofed_version} | sed -r 'y/-/_/; s/\.el[0-9_]+\.%{_arch}$//;')
%global dash_ofed -ofed
%endif

%description
This package contains the kernel modules
for the DRBD core and various transports.

# The kernel_module_package macro takes _files_ as parameters.
# I don't want to ship a number of files for a number of variants
# as "SourceX:".
# So this is my attempt at using "conditional here docs" in an rpm spec file.
# Careful with quoting, %% or \\ need to be doubled here.

%define shell_to_tmpfile(n:c:) %{expand:%(( set -e;                     \
        tmp=$(mktemp %{_tmppath}/%{name}.rpmbuild.%{-n*}.tmp.XXXXXX)    \
        tmp_files="%{?my_tmp_files_to_be_removed_in_prep} $tmp"         \
        echo %%global my_tmp_files_to_be_removed_in_prep $tmp_files %%{nil}     \
        echo %%global %{-n*} $tmp                                       \
        ( %* ) > $tmp                                                   \
        ); [[ $? = 0 ]] || echo %%error failed)}

%{shell_to_tmpfile -n files_suse_kmod_drbd printf "%%s\\n" \
	"%%defattr(-,root,root)" \
	"/lib/modules/%%2-%%1" \
	"%%doc COPYING" \
	"%%doc ChangeLog" \
	"%%doc drbd/k-config-%%2-%%1.gz" \
}
%{shell_to_tmpfile -n files_rh_kmod_drbd printf "%%s\\n" \
	"%%defattr(644,root,root,755)" \
	"/lib/modules/%%verrel%%dotvariant/extra/drbd" \
	"%%doc COPYING" \
	"%%doc ChangeLog" \
	"%%doc drbd/k-config-%%verrel%%dotvariant.gz" \
	"%%config /etc/depmod.d/drbd.conf" \
	"%%config /etc/pki/linbit/SECURE-BOOT-KEY-linbit.com.der" \
}

%if %{defined suse_kernel_module_package}
# Support also sles10, where kernel_module_package was not yet defined.
# In sles11, suse_k_m_p became a wrapper around k_m_p.

%if 0%{?suse_version} < 1110
# We need to exclude some flavours on sles10 etc,
# or we hit an rpm internal buffer limit.
%suse_kernel_module_package -n drbd -f %{files_suse_kmod_drbd} kdump kdumppae vmi vmipae um
%else
%suse_kernel_module_package -n drbd -f %{files_suse_kmod_drbd}
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
%global _this_latest_kernel_devel %({
	rpm -q --qf '%%{VERSION}-%%{RELEASE}.%%{ARCH}\\n' \\
		$(rpm -qa | egrep "^kernel(-rt|-aarch64)?-devel" | /usr/lib/rpm/redhat/rpmsort -r);
	echo '%%{nil}'; } | head -n 1)
%if 0%{!?kernel_version:1}
%global kernel_version %_this_latest_kernel_devel
%{warn: "XXX selected %kernel_version based on installed kernel-*devel packages"}
%endif
%global _this_kmp_version %{version}_%(echo %{kernel_version} | sed -r 'y/-/_/; s/\.el[0-9_]+\.%{_arch}$//;')%{?_ofed_version_nodash}

%kernel_module_package -n drbd -v %_this_kmp_version -f %{files_rh_kmod_drbd} %{?lb_flavors}

%endif

%prep
rm -f %{?my_tmp_files_to_be_removed_in_prep}
%setup -q -n drbd-%{tarball_version}

%build
for flavor in %flavors_to_build; do
    make -C drbd %{_smp_mflags} all KDIR=%{kernel_source $flavor} \
	%{?_ofed_version:BUILD_OFED=1} \
	%{?ofed_kernel_dir:OFED_KERNEL_DIR=%{ofed_kernel_dir}} \
	%{?_ofed_version:OFED_VERSION=%{_ofed_version}} \
	%{?with_gcov:GCOV_PROFILE=y}
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
    make -C drbd install KDIR=%{kernel_source $flavor} \
	%{?_ofed_version:BUILD_OFED=1} \
	%{?ofed_kernel_dir:OFED_KERNEL_DIR=%{ofed_kernel_dir}} \
	%{?_ofed_version:OFED_VERSION=%{_ofed_version}} \
	%{?with_gcov:GCOV_PROFILE=y} \
	cmd_depmod=:
    kernelrelease=$(cat %{kernel_source $flavor}/include/config/kernel.release || make -s -C %{kernel_source $flavor} kernelrelease)
    mv drbd/build-current/.kernel.config.gz drbd/k-config-$kernelrelease.gz
done

%if %{defined suse_kernel_module_package}
# On SUSE, putting the modules into the default path determined by
# %kernel_module_package_moddir is enough to give them priority over
# shipped modules.
rm -f drbd.conf
%else

mkdir -p $RPM_BUILD_ROOT/etc/depmod.d
find $RPM_BUILD_ROOT/lib/modules/*/ -name "*.ko"  -printf "%%P\n" |
sort | sed -ne 's,^extra/\(.*\)/\([^/]*\)\.ko$,\2 \1,p' |
xargs -r printf "override %%-16s * weak-updates/%%s\n" \
> $RPM_BUILD_ROOT/etc/depmod.d/drbd.conf
install -D misc/SECURE-BOOT-KEY-linbit.com.der $RPM_BUILD_ROOT/etc/pki/linbit/SECURE-BOOT-KEY-linbit.com.der
%endif

%clean
rm -rf %{buildroot}

%changelog
* Mon Jun  3 2024 Philipp Reisner <phil@linbit.com> - 9.2.10
-  New upstream release.

* Tue Apr 30 2024 Philipp Reisner <phil@linbit.com> - 9.2.9
-  New upstream release.

* Tue Mar 05 2024 Philipp Reisner <phil@linbit.com> - 9.2.8
-  New upstream release.

* Wed Dec 22 2023 Philipp Reisner <phil@linbit.com> - 9.2.7
-  New upstream release.

* Tue Oct 31 2023 Philipp Reisner <phil@linbit.com> - 9.2.6
-  New upstream release.

* Wed Aug 09 2023 Philipp Reisner <phil@linbit.com> - 9.2.5
-  New upstream release.

* Mon Jun 05 2023 Philipp Reisner <phil@linbit.com> - 9.2.4
-  New upstream release.

* Tue Apr 04 2023 Philipp Reisner <phil@linbit.com> - 9.2.3
-  New upstream release.

* Mon Jan 30 2023 Philipp Reisner <phil@linbit.com> - 9.2.2
-  New upstream release.

* Mon Nov 14 2022 Philipp Reisner <phil@linbit.com> - 9.2.1
-  New upstream release.

* Mon Oct 10 2022 Philipp Reisner <phil@linbit.com> - 9.2.0
-  New upstream release.
