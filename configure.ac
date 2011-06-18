dnl Process this file with autoconf 2.52+ to produce a configure script.
dnl
dnl Copyright (C) 2001 Philipp Rumpf
dnl Copyright (C) 2004,2010 Henrique de Moraes Holschuh <hmh@debian.org>
dnl
dnl This program is free software; you can redistribute it and/or modify
dnl it under the terms of the GNU General Public License as published by
dnl the Free Software Foundation; either version 2 of the License, or
dnl (at your option) any later version.
dnl
dnl This program is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl GNU General Public License for more details.
dnl
dnl You should have received a copy of the GNU General Public License
dnl along with this program; if not, write to the Free Software
dnl Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

AC_INIT([rng-tools], [2-unofficial-mt.14], [rng-tools@packages.debian.org])
AC_PREREQ([2.59])
AC_CONFIG_SRCDIR([rngd.c])
AC_CANONICAL_HOST
AM_INIT_AUTOMAKE([1.9 gnu])
AC_CONFIG_HEADERS([rng-tools-config.h])

dnl Make sure anyone changing configure.ac/Makefile.am has a clue
AM_MAINTAINER_MODE

dnl Checks for programs
AC_PROG_CC
AC_PROG_RANLIB
AC_PROG_GCC_TRADITIONAL

dnl Checks for header files.
dnl AC_HEADER_STDC
dnl AC_CHECK_HEADERS([sys/ioctl.h unistd.h])

dnl Checks for typedefs, structures, and compiler characteristics.
dnl AC_TYPE_SIZE_T
dnl AC_TYPE_PID_T

dnl LARGE_FILE support is absolutely required for VIA PadLock support,
dnl and a good idea anyway.  Turn it off at your own risk...
AC_SYS_LARGEFILE

dnl -----------------------------
dnl Checks for required libraries
dnl -----------------------------
AC_CHECK_LIB([pthread], [pthread_create],
	     [LIB_PTHREAD="-lpthread"], 
	     [AC_MSG_ERROR([Can't compile without pthreads])])
AC_SUBST(LIB_PTHREAD)

dnl -------------------------------------
dnl Checks for optional library functions
dnl -------------------------------------

dnl -----------------
dnl Configure options
dnl -----------------

SYSLOG_FACILITY=LOG_DAEMON
AC_ARG_WITH([syslogfacility],
	[AS_HELP_STRING([--with-syslogfacility=FACILITY],
		[syslog facility (default DAEMON)])],
	[ if test "$withval" != "yes" -a "$withval" != "no" ; then
		SYSLOG_FACILITY=LOG_$withval
	  fi; ])
AC_DEFINE_UNQUOTED(SYSLOG_FACILITY, $SYSLOG_FACILITY, [Syslog facility to use.])

AC_ARG_WITH([pidfile],
	[AS_HELP_STRING([--with-pidfile=PATH],
		[pidfile in PATH (/var/run/rngd.pid)])],
	[PIDFILE="$withval"],
	[PIDFILE="/var/run/rngd.pid"])
AC_DEFINE_UNQUOTED(PIDFILE, "$PIDFILE",[Name of the pidfile for rngd])
AC_SUBST(PIDFILE)

AC_ARG_WITH([kernelrng],
	[AS_HELP_STRING([--with-kernelrng=PATH],
		[Kernel RNG device in PATH (/dev/random)])],
	[DEVRANDOM="$withval"],
	[DEVRANDOM="/dev/random"])
AC_DEFINE_UNQUOTED(DEVRANDOM, "$DEVRANDOM", [Name of the kernel RNG device])
AC_SUBST(DEVRANDOM)

AC_ARG_WITH([hwrng],
	[AS_HELP_STRING([--with-hwrng=PATH],
		[Source HRNG device in PATH (/dev/hwrng)])],
	[DEVHWRANDOM="$withval"],
	[DEVHWRANDOM="/dev/hwrng"])
AC_DEFINE_UNQUOTED(DEVHWRANDOM, "$DEVHWRANDOM",
	[Name of the source HRNG device])
AC_SUBST(DEVHWRANDOM)

AC_ARG_ENABLE(viapadlock,
	AS_HELP_STRING([--enable-viapadlock],
		[Enable suport for VIA PadLock TRNG entropy source (detect)]),
	[VIADRIVER="$enableval"],
	[VIADRIVER="no"
	 AS_IF(test "$host_cpu" == "i586" || test "$host_cpu" == "i686" ||
	       test "$host_cpu" == "x86_64" ,
	 	[VIADRIVER="yes"])
	])
AC_MSG_CHECKING([whether to include the VIA PadLock TRNG driver])
AS_IF(test "$VIADRIVER" == "yes",
	[AC_DEFINE(VIA_ENTSOURCE_DRIVER, 1, 
		[Include code for VIA PadLock TRNG driver])
	 AC_MSG_RESULT([yes]) ],
	[AC_MSG_RESULT([no])] )

dnl --------------------------
dnl autoconf output generation
dnl --------------------------

AC_CONFIG_FILES([Makefile contrib/Makefile rngd.8 rngtest.1])
AC_OUTPUT
