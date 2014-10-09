AC_PREREQ(2.61)
AC_INIT(google-authenticator, 1.01, habets@google.com)
LT_INIT
AC_CANONICAL_SYSTEM
AC_CONFIG_MACRO_DIR([m4])
#ACLOCAL_AMFLAGS([-I m4])
AC_CONFIG_SRCDIR([google-authenticator.c])
AM_INIT_AUTOMAKE([foreign subdir-objects])
AM_MAINTAINER_MODE
AC_CONFIG_HEADER(config.h)

# Checks for programs.
AC_PROG_CC
AC_PROG_CC_STDC
AC_PROG_INSTALL
AC_PROG_MAKE_SET

AC_CHECK_HEADERS([\
sys/fsuid.h \
])
AC_CHECK_LIB([dl], [dlopen])

AC_CHECK_FUNCS([setfsuid])

LT_OUTPUT
if test ! "$export_dynamic_flag_spec" = ""; then
   eval `libtool --tag=CC --config | grep '^wl='`
   RDYNAMIC_FLAG=`echo echo $export_dynamic_flag_spec | sh`
fi
AC_SUBST(RDYNAMIC_FLAG)

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

echo "
  $PACKAGE_NAME version $PACKAGE_VERSION
  Prefix.........: $prefix
  Debug Build....: $debug
  C Compiler.....: $CC $CFLAGS $CPPFLAGS
  Linker.........: $LD $LDFLAGS $LIBS
"
