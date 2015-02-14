pamdir = $(libdir)/security

bin_PROGRAMS=google-authenticator
pam_LTLIBRARIES=pam_google_authenticator.la
noinst_PROGRAMS=demo pam_google_authenticator_unittest
check_LTLIBRARIES=libpam_google_authenticator_testing.la

dist_doc_DATA = FILEFORMAT README
dist_html_DATA = totp.html

MODULES_LDFLAGS = -avoid-version -module -shared -export-dynamic

demo_SOURCES=\
pam_google_authenticator.c \
demo.c \
base32.c \
base32.h \
hmac.c \
hmac.h \
sha1.c \
sha1.h
demo_CFLAGS=$(AM_CFLAGS) -DDEMO=1

google_authenticator_SOURCES=\
google-authenticator.c \
base32.c \
base32.h \
hmac.c \
hmac.h \
sha1.c \
sha1.h

TESTS=pam_google_authenticator_unittest
pam_google_authenticator_unittest_SOURCES=\
pam_google_authenticator_unittest.c \
base32.c \
base32.h \
hmac.c \
hmac.h \
sha1.c \
sha1.h
pam_google_authenticator_unittest_LDFLAGS=$(AM_LDFLAGS) -export-dynamic

pam_google_authenticator_la_SOURCES=\
pam_google_authenticator.c \
base32.c \
base32.h \
hmac.c \
hmac.h \
sha1.c \
sha1.h
pam_google_authenticator_la_LIBADD = -lpam
pam_google_authenticator_la_CFLAGS=$(AM_CFLAGS)
pam_google_authenticator_la_LDFLAGS=$(AM_LDFLAGS) $(MODULES_LDFLAGS) -export-symbols-regex "pam_sm_(setcred|open_session|authenticate)"

libpam_google_authenticator_testing_la_SOURCES=\
pam_google_authenticator.c \
base32.c \
base32.h \
hmac.c \
hmac.h \
sha1.c \
sha1.h
libpam_google_authenticator_testing_la_CFLAGS=$(AM_CFLAGS) -DTESTING=1
libpam_google_authenticator_testing_la_LDFLAGS=$(AM_LDFLAGS) $(MODULES_LDFLAGS) -rpath $(abs_top_builddir)


super-clean: maintainer-clean
	rm -fr aclocal autom4te.cache/ m4 missing libtool config.guess
	rm -fr config.lt config.status config.sub configure depcomp
	rm -fr libtool install-sh  *~ Makefile aclocal.m4 config.h.in ltmain.sh
	rm -fr Makefile.in test-driver compile
