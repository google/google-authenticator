AC_PREREQ(2.61)
AC_INIT(google-authenticator, 1.02, habets@google.com)
AC_CONFIG_SRCDIR([src/google-authenticator.c])
AC_CONFIG_AUX_DIR([build])
AC_CONFIG_MACRO_DIR([build])

AC_USE_SYSTEM_EXTENSIONS
AM_INIT_AUTOMAKE([foreign subdir-objects])
AM_MAINTAINER_MODE([enable])

LT_INIT
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

AC_MSG_CHECKING([whether certain PAM functions require const arguments])
AC_LANG_PUSH(C)
# Force test to bail if const isn't needed
AC_LANG_WERROR
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
	#include <security/pam_appl.h>
	#include <security/pam_modules.h>
]],[[
	const void **item = 0;
	int dummy = 0;
	/*
	 * since pam_handle_t is opaque on at least some platforms, give it
	 * a non-NULL dummy value
	 */
	 const pam_handle_t *ph = (const pam_handle_t *)&dummy;
	(void) pam_get_item(ph, 0, item);
]])],[AC_DEFINE([PAM_CONST], [const], \
	[Define if certain PAM functions require const arguments])
		AC_MSG_RESULT([yes])],
	[AC_DEFINE([PAM_CONST], [], \
	[Prevent certain PAM functions from using const arguments])
	AC_MSG_RESULT([no])])
AC_LANG_POP(C)

AC_SEARCH_LIBS([dlopen], [dl])

AC_CONFIG_HEADER(config.h)
AC_CONFIG_FILES([Makefile contrib/rpm.spec])
AC_OUTPUT

echo "
  $PACKAGE_NAME version $PACKAGE_VERSION
  Prefix.........: $prefix
  Debug Build....: $debug
  C Compiler.....: $CC $CFLAGS $CPPFLAGS
  Linker.........: $LD $LDFLAGS $LIBS
"
