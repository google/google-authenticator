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

AC_CHECK_HEADERS_ONCE([security/pam_appl.h])
# On Solaris at least, <security/pam_modules.h> requires <security/pam_appl.h>
# to be included first
AC_CHECK_HEADER([security/pam_modules.h], [], [], \
		[#ifdef HAVE_SECURITY_PAM_APPL_H
		# include <security/pam_appl.h>
		#endif
		])
AC_CHECK_LIB([pam], [pam_get_user], [:])
AS_IF([test "x$ac_cv_header_security_pam_modules_h" = "xno" \
       -o "x$ac_cv_lib_pam_pam_get_user" = "xno"], [
  AC_MSG_ERROR([Unable to find the PAM library or the PAM header files])
])


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
