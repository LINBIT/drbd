dnl
dnl autoconf for DRBD
dnl
dnl License: GNU General Public License Version 2 (GPLv2)

dnl Minimum autoconf version we require
AC_PREREQ(2.53)

dnl What we are, our version, who to bug in case of problems
AC_INIT(DRBD, 8.3.4, [drbd-dev@lists.linbit.com])

dnl "--with-<foo>" options (all enabled by default, pass --without-<foo> to disable)
WITH_UTILS=yes
WITH_KM=yes
WITH_UDEV=yes
WITH_XEN=yes
WITH_PACEMAKER=yes
WITH_HEARTBEAT=yes
WITH_RGMANAGER=yes
WITH_BASHCOMPLETION=yes
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
AC_PROG_SED
AC_PROG_GREP
AC_PATH_PROG(FLEX, flex)
AC_PATH_PROG(RPMBUILD, rpmbuild)
AC_PATH_PROG(XSLTPROC, xsltproc)
AC_PATH_PROG(TAR, tar)
AC_PATH_PROG(GIT, git)
AC_PATH_PROG(DPKG_BUILDPACKAGE, dpkg-buildpackage)

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

dnl Checks for system services
KVER="`uname -r`"
KDIR="/lib/modules/$KVER/build"
AC_SUBST(KVER)
AC_SUBST(KDIR)
if test "$WITH_KM" = "yes"; then
   AC_CHECK_FILE($KDIR/Makefile,
		,
      		AC_MSG_WARN([Unable to find a kernel Makefile in $KDIR. You will have to set KDIR correctly when invoking make.]))
fi

dnl The configuration files we create (from their .in template)
AC_CONFIG_FILES(Makefile drbd.spec)

dnl output
AC_OUTPUT
