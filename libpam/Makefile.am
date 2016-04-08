AUTOMAKE_OPTIONS = foreign subdir-objects
ACLOCAL_AMFLAGS = -I build

pamdir = $(libdir)/security

bin_PROGRAMS      = google-authenticator
pam_LTLIBRARIES   = pam_google_authenticator.la

dist_doc_DATA  = FILEFORMAT README.md
dist_html_DATA = totp.html

MODULES_LDFLAGS = -avoid-version -module -shared -export-dynamic

CORE_SRC  =
CORE_SRC += src/base32.h src/base32.c
CORE_SRC += src/hmac.h   src/hmac.c
CORE_SRC += src/sha1.h   src/sha1.c


google_authenticator_SOURCES = \
	src/google-authenticator.c \
	$(CORE_SRC)

pam_google_authenticator_la_SOURCES = \
	src/pam_google_authenticator.c \
	$(CORE_SRC)
pam_google_authenticator_la_LIBADD  = -lpam
pam_google_authenticator_la_CFLAGS  = $(AM_CFLAGS)
pam_google_authenticator_la_LDFLAGS = $(AM_LDFLAGS) $(MODULES_LDFLAGS) -export-symbols-regex "pam_sm_(setcred|open_session|authenticate)"


check_PROGRAMS    = examples/demo tests/pam_google_authenticator_unittest
check_LTLIBRARIES = libpam_google_authenticator_testing.la
TESTS             = tests/pam_google_authenticator_unittest

libpam_google_authenticator_testing_la_SOURCES = \
	src/pam_google_authenticator.c \
	$(CORE_SRC)
libpam_google_authenticator_testing_la_CFLAGS  = $(AM_CFLAGS) -DTESTING=1
libpam_google_authenticator_testing_la_LDFLAGS = $(AM_LDFLAGS) $(MODULES_LDFLAGS) -rpath $(abs_top_builddir)

tests_pam_google_authenticator_unittest_SOURCES = \
	tests/pam_google_authenticator_unittest.c \
	$(CORE_SRC)
tests_pam_google_authenticator_unittest_LDFLAGS = $(AM_LDFLAGS) -export-dynamic

test: check


examples_demo_SOURCES = \
	src/pam_google_authenticator.c \
	$(CORE_SRC) \
	examples/demo.c
examples_demo_CFLAGS = $(AM_CFLAGS) -DDEMO=1


super-clean: maintainer-clean
	rm -fr aclocal autom4te.cache/ m4 missing libtool config.guess
	rm -fr config.lt config.status config.sub configure depcomp
	rm -fr libtool install-sh  *~ Makefile aclocal.m4 config.h.in ltmain.sh
	rm -fr Makefile.in test-driver compile
