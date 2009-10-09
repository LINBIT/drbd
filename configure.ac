dnl
dnl autoconf for DRBD
dnl
dnl License: GNU General Public License Version 2 (GPLv2)

dnl Minimum autoconf version we require
AC_PREREQ(2.53)

dnl What we are, our version, who to bug in case of problems
AC_INIT(DRBD, 8.3.4, [drbd-dev@lists.linbit.com])

dnl "--with-<foo>" options
AC_ARG_WITH([utils],
	[AS_HELP_STRING([--with-utils],
			[Enable management utilities])],
	[with_utils=$withval],
	[with_utils=yes])
AC_ARG_WITH([km],
	[AS_HELP_STRING([--with-km],
			[Enable kernel module])],
	[],
	[with_km=yes])
AC_ARG_WITH([udev],
	[AS_HELP_STRING([--with-udev],
			[Enable udev integration])],
	[],
	[with_udev=yes])
AC_ARG_WITH([xen],
	[AS_HELP_STRING([--with-xen],
			[Enable Xen integration])],
	[],
	[with_xen=yes])
AC_ARG_WITH([pacemaker],
	[AS_HELP_STRING([--with-pacemaker],
			[Enable Pacemaker integration])],
	[],
	[with_pacemaker=yes])
AC_ARG_WITH([heartbeat],
	[AS_HELP_STRING([--with-heartbeat],
			[Enable Heartbeat integration])],
	[],
	[with_heartbeat=yes])
AC_ARG_WITH([rgmanager],
	[AS_HELP_STRING([--with-rgmanager],
			[Enable Red Hat Cluster Suite integration])],
	[],
	[with_rgmanager=yes])
AC_ARG_WITH([bashcompletion],
	[AS_HELP_STRING([--with-bashcompletion],
			[Enable programmable bash completion])],
	[],
	[with_bashcompletion=yes])

dnl Checks for programs
AC_PROG_CC
AC_PROG_LN_S
AC_PROG_SED
AC_PROG_GREP
AC_CHECK_PROG([FLEX], [flex])
AC_CHECK_PROG([RPMBUILD], [rpmbuild])

dnl Variable substitutions
AC_SUBST(CFLAGS)
AC_SUBST(CC)
AC_SUBST(MAKE)

dnl The configuration files we create (from their .in template)
AC_CONFIG_FILES(Makefile drbd.spec)

dnl output
AC_OUTPUT
