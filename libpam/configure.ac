AC_PREREQ(2.61)
AC_INIT(google-authenticator, 1.01, habets@google.com)
LT_INIT
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([google-authenticator.c])
AM_INIT_AUTOMAKE([foreign subdir-objects])
AM_MAINTAINER_MODE([enable])
AC_CONFIG_HEADER(config.h)

AC_PROG_CC
AC_PROG_CC_STDC

AC_CHECK_HEADERS([sys/fsuid.h])
AC_CHECK_FUNCS([setfsuid])

AC_SEARCH_LIBS([dlopen], [dl])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

echo "
  $PACKAGE_NAME version $PACKAGE_VERSION
  Prefix.........: $prefix
  Debug Build....: $debug
  C Compiler.....: $CC $CFLAGS $CPPFLAGS
  Linker.........: $LD $LDFLAGS $LIBS
"
