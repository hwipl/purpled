#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT(FULL-PACKAGE-NAME, VERSION, BUG-REPORT-ADDRESS)
AC_CONFIG_SRCDIR([defines.h])
AC_CONFIG_HEADER([config.h])
#AC_CANONICAL_SYSTEM

# Checks for programs.
AC_PROG_CC
#m4_include([/usr/share/aclocal/pkg.m4])

#PKG_CHECK_MODULES
PKG_PROG_PKG_CONFIG

# Checks for libraries.
# FIXME: Replace `main' with a function in `-lpurple':
AC_CHECK_LIB([purple], [main])
PKG_CHECK_MODULES(GLIB, glib-2.0 >= 2.0)
PKG_CHECK_MODULES(PURPLE, purple)

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([netinet/in.h string.h sys/socket.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_PID_T
AC_TYPE_UID_T

# Checks for library functions.
AC_FUNC_FORK
AC_TYPE_SIGNAL
AC_CHECK_FUNCS([bzero inet_ntoa socket strcasecmp])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
