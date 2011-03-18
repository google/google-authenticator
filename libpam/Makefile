
# Copyright 2010 Google Inc.
# Author: Markus Gutschke
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

.SUFFIXES: .so

all: google-authenticator pam_google_authenticator.so demo                    \
     pam_google_authenticator_unittest

test: pam_google_authenticator_unittest
	./pam_google_authenticator_unittest

install: all
	@dst=/lib$$([ -d /lib64/security ] && echo 64)/security;              \
	[ -d "$${dst}" ] || dst=/usr/lib;                                     \
	sudo=; if [ $$(id -u) -ne 0 ]; then                                   \
	  echo "You need to be root to install this module.";                 \
	  if [ -x /usr/bin/sudo ]; then                                       \
	    echo "Invoking sudo:";                                            \
	    sudo=sudo;                                                        \
	  else                                                                \
	    exit 1;                                                           \
	  fi;                                                                 \
	fi;                                                                   \
	echo cp pam_google_authenticator.so $${dst};                          \
	tar fc - pam_google_authenticator.so | $${sudo} tar ofxC - $${dst};   \
	                                                                      \
	echo cp google-authenticator /usr/local/bin;                          \
	tar fc - google-authenticator | $${sudo} tar ofxC - /usr/local/bin;   \
	$${sudo} chmod 755 $${dst}/pam_google_authenticator.so                \
	                   /usr/local/bin/google-authenticator

clean:
	$(RM) *.o *.so google-authenticator demo pam_google_authenticator_demo\
	               pam_google_authenticator_unittest

google-authenticator: google-authenticator.o base32.o hmac.o sha1.o
	$(CC) -g $(LDFLAGS) $(shell [ -f /usr/lib/libdl.so ] && echo " -ldl") \
	      -o $@ $+

demo: demo.o
	$(CC) -g $(LDFLAGS) -rdynamic                                         \
	      $(shell [ -f /usr/lib/libdl.so ] && echo " -ldl") -o $@ $+

pam_google_authenticator_unittest: pam_google_authenticator_unittest.o        \
                                   base32.o hmac.o sha1.o
	$(CC) -g $(LDFLAGS) -rdynamic -lc                                     \
              $(shell [ -f /usr/lib/libdl.so ] && echo " -ldl")               \
              -o $@ $+

pam_google_authenticator.so: base32.o hmac.o sha1.o
pam_google_authenticator_demo.so: base32.o hmac.o sha1.o
pam_google_authenticator_testing.so: base32.o hmac.o sha1.o

pam_google_authenticator.o: pam_google_authenticator.c base32.h hmac.h sha1.h
pam_google_authenticator_demo.o: pam_google_authenticator.c base32.h hmac.h   \
	                         sha1.h
	$(CC) -DDEMO --std=gnu99 -Wall -O2 -g -fPIC -c $(CFLAGS) -o $@ $<
pam_google_authenticator_testing.o: pam_google_authenticator.c base32.h       \
                                    hmac.h sha1.h
	$(CC) -DTESTING --std=gnu99 -Wall -O2 -g -fPIC -c $(CFLAGS) -o $@ $<
demo.o: demo.c pam_google_authenticator_demo.so
pam_google_authenticator_unittest.o: pam_google_authenticator_unittest.c      \
                                     pam_google_authenticator_testing.so      \
                                     base32.h hmac.h sha1.h
google-authenticator.o: google-authenticator.c base32.h hmac.h sha1.h
base32.o: base32.c base32.h
hmac.o: hmac.c hmac.h sha1.h
sha1.o: sha1.c sha1.h

.c.o:
	$(CC) --std=gnu99 -Wall -O2 -g -fPIC -c $(CFLAGS) -o $@ $<
.o.so:
	$(CC) -shared -g $(LDFLAGS) -o $@ $+
