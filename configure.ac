dnl
dnl autoconf for DRBD
dnl
dnl License: GNU General Public License Version 2 (GPLv2)

dnl Minimum autoconf version we require
AC_PREREQ(2.53)

dnl What we are, our version, who to bug in case of problems
AC_INIT(DRBD, 8.3.4, [drbd-dev@lists.linbit.com])

dnl "--with-<foo>" options (all except km enabled by default, pass --without-<foo> to disable)
WITH_UTILS=yes
WITH_KM=no
WITH_UDEV=yes
WITH_XEN=yes
WITH_PACEMAKER=yes
WITH_HEARTBEAT=yes
WITH_RGMANAGER=no
WITH_BASHCOMPLETION=yes
WITH_NOARCH_SUBPACKAGES=no
AC_ARG_WITH([utils],
	[AS_HELP_STRING([--with-utils],
			[Enable management utilities])],
	[WITH_UTILS=$withval])
AC_ARG_WITH([km],
	[AS_HELP_STRING([--with-km],
			[Enable kernel module])],
	[WITH_KM=$withval])
AC_ARG_WITH([udev],
	[AS_HELP_STRING([--with-udev],
			[Enable udev integration])],
	[WITH_UDEV=$withval])
AC_ARG_WITH([xen],
	[AS_HELP_STRING([--with-xen],
			[Enable Xen integration])],
	[WITH_XEN=$withval])
AC_ARG_WITH([pacemaker],
	[AS_HELP_STRING([--with-pacemaker],
			[Enable Pacemaker integration])],
	[WITH_PACEMAKER=$withval])
AC_ARG_WITH([heartbeat],
	[AS_HELP_STRING([--with-heartbeat],
			[Enable Heartbeat integration])],
	[WITH_HEARTBEAT=$withval])
AC_ARG_WITH([rgmanager],
	[AS_HELP_STRING([--with-rgmanager],
			[Enable Red Hat Cluster Suite integration])],
	[WITH_RGMANAGER=$withval])
AC_ARG_WITH([bashcompletion],
	[AS_HELP_STRING([--with-bashcompletion],
			[Enable programmable bash completion])],
	[WITH_BASHCOMPLETION=$withval])
AC_ARG_WITH([distro],
	[AS_HELP_STRING([--with-distro],
			[Configure for a specific distribution (supported values: generic, redhat, suse, debian, gentoo, slackware; default is to autodetect)])],
	[DISTRO=$withval])
AC_ARG_WITH([noarchsubpkg],
	[AS_HELP_STRING([--with-noarchsubpkg],
			[Build subpackages that support it for the "noarch" architecture (makes sense only with --enable-spec, supported by RPM from 4.6.0 forward)])],
	[WITH_NOARCH_SUBPACKAGES=$withval])
AC_ARG_ENABLE([spec],
	[AS_HELP_STRING([--enable-spec],
			[Rather than creating Makefiles, create an RPM spec file only])],
	[SPECMODE=$enableval],
	[SPECMODE=""])


AC_SUBST(WITH_UTILS)
AC_SUBST(WITH_KM)
AC_SUBST(WITH_UDEV)
AC_SUBST(WITH_XEN)
AC_SUBST(WITH_PACEMAKER)
AC_SUBST(WITH_HEARTBEAT)
AC_SUBST(WITH_RGMANAGER)
AC_SUBST(WITH_BASHCOMPLETION)


dnl Checks for programs
AC_PROG_CC
AC_PROG_LN_S
AC_PATH_PROG(SED, sed)
AC_PATH_PROG(GREP, grep)
AC_PATH_PROG(FLEX, flex)
AC_PATH_PROG(RPMBUILD, rpmbuild)
AC_PATH_PROG(XSLTPROC, xsltproc)
AC_PATH_PROG(TAR, tar)
AC_PATH_PROG(GIT, git)
AC_PATH_PROG(DPKG_BUILDPACKAGE, dpkg-buildpackage)
AC_PATH_PROG(UDEVADM, udevadm)
AC_PATH_PROG(UDEVINFO, udevinfo)

if test -z $CC; then
   if test "$WITH_UTILS" = "yes"; then
      AC_MSG_ERROR([Cannot build utils without a C compiler, either install a compiler or pass the --without-utils option.])
   fi 
   if test "$WITH_KM" = "yes"; then
      AC_MSG_ERROR([Cannot build kernel module without a C compiler, either install a compiler or pass the --without-km option.])
   fi
fi

if test -z $FLEX; then
   if test "$WITH_UTILS" = "yes"; then
     AC_MSG_ERROR([Cannot build utils without flex, either install flex or pass the --without-utils option.])
   fi
fi

if test -z $RPMBUILD; then
   AC_MSG_WARN([No rpmbuild found, building RPM packages is disabled.])
fi

if test -z $DPKG_BUILDPACKAGE; then
   AC_MSG_WARN([No dpkg-buildpackage found, building Debian packages is disabled.])
fi

if test -z $XSLTPROC; then
   AC_MSG_WARN([Cannot build man pages without xsltproc. You may safely ignore this warning when building from a tarball.])
fi

if test -z $GIT; then
   AC_MSG_WARN(Cannot update buildtag without git. You may safely ignore this warning when building from a tarball.)
fi

if test -z $UDEVADM && test -z $UDEVINFO; then
   if test "$WITH_UDEV" = "yes"; then
     AC_MSG_WARN([udev support enabled, but neither udevadm nor udevinfo found on this system.])
   fi
fi


dnl Checks for system services

dnl figure out the kernel versin and kernel headers directory
if test "$WITH_KM" = "yes"; then
   AC_CHECK_FILE($KDIR/Makefile,
		,
      		AC_MSG_WARN([Unable to find a kernel Makefile in $KDIR. You will have to set KDIR correctly when invoking make.]))
   KVER="`uname -r`"
   KDIR="/lib/modules/$KVER/build"
fi
AC_SUBST(KVER)
AC_SUBST(KDIR)

INITDIR="$sysconfdir/init.d"
BASH_COMPLETION_SUFFIX=""
UDEV_RULE_SUFFIX=""
RPM_DIST_TAG=""
RPM_CONFLICTS_KM=""
RPM_BUILDREQ_KM=""
RPM_SUBPACKAGE_NOARCH=""
INITSCRIPT_SYMLINK=""
dnl figure out the distribution we're running on, and set some variables accordingly
if test -z $DISTRO; then
   AC_CHECK_FILE(/etc/gentoo-release, [DISTRO="gentoo"])
   AC_CHECK_FILE(/etc/redhat-release, [DISTRO="redhat"])
   AC_CHECK_FILE(/etc/slackware-version, [DISTRO="slackware"])
   AC_CHECK_FILE(/etc/debian_version, [DISTRO="debian"])
   AC_CHECK_FILE(/etc/SuSErelease, [DISTRO="suse"])
fi
case "$DISTRO" in
     gentoo)
	AC_MSG_NOTICE([configured for Gentoo.])
	;;
     redhat)
	INITDIR="$sysconfdir/rc.d/init.d"
	RPM_DIST_TAG="%{?dist}"
	RPM_CONFLICTS_KM="drbd-kmod <= %{version}_3"
	RPM_BUILDREQ_KM="kernel-devel = %{kernelversion}"
	AC_MSG_NOTICE([configured for Red Hat (includes Fedora, RHEL, CentOS).])
	;;
     slackware)
	INITDIR="$sysconfdir/rc.d"
	AC_MSG_NOTICE([configured for Slackware.])
	;;
     debian)
	AC_MSG_NOTICE([configured for Debian (includes Ubuntu).])
        ;;
     suse)
	BASH_COMPLETION_SUFFIX=".sh"
	RPM_CONFLICTS_KM="km_drbd, drbd-kmp <= %{version}_3"
	RPM_BUILDREQ_KM="kernel-syms = %{kernelversion}"
	INITSCRIPT_SYMLINK="/sbin/rcdrbd"
	AC_MSG_NOTICE([configured for SUSE (includes openSUSE, SLES).])
	;;
     "")
	AC_MSG_WARN([Unable to determine what distribution we are running on. Distribution-specific features will be disabled.])
	;;
esac

dnl Our udev rules file is known to work only with udev >= 85
if test "$WITH_UDEV" = "yes"; then
   udev_version=`$UDEVADM version 2>/dev/null` || udev_version=`$UDEVINFO -V | cut -d " " -f 3` || udev_version=0
   if test $udev_version -lt 85; then
      UDEV_RULE_SUFFIX=".disabled"
      AC_MSG_WARN([Obsolete or unknown udev version. Installing disabled udev rules.])
   fi
fi

dnl Our sub-packages can be built for noarch, but RPM only supports this from version 4.6.0 forward
if test "$WITH_NOARCH_SUBPACKAGES" = "yes"; then
   RPM_SUBPACKAGE_NOARCH="BuildArch: noarch"
fi
AC_SUBST(DISTRO)
AC_SUBST(INITDIR)
AC_SUBST(BASH_COMPLETION_SUFFIX)
AC_SUBST(UDEV_RULE_SUFFIX)
AC_SUBST(RPM_DIST_TAG)
AC_SUBST(RPM_CONFLICTS_KM)
AC_SUBST(RPM_BUILDREQ_KM)
AC_SUBST(RPM_SUBPACKAGE_NOARCH)
AC_SUBST(INITSCRIPT_SYMLINK)

dnl The configuration files we create (from their .in template)
if test -z $SPECMODE; then
   AC_CONFIG_FILES(Makefile user/Makefile scripts/Makefile documentation/Makefile)
else
   AC_CONFIG_FILES(drbd.spec)
   AC_CONFIG_FILES(drbd-km.spec)
fi

dnl output
AC_OUTPUT
