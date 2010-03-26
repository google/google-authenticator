// Unittest for the PAM module. This is part of the Google Authenticator
// project.
//
// Copyright 2010 Google Inc.
// Author: Markus Gutschke
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <assert.h>
#include <dlfcn.h>
#include <security/pam_modules.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "base32.h"

static char *response;

static int conversation(int num_msg, const struct pam_message **msg,
                        struct pam_response **resp, void *appdata_ptr) {
  if (num_msg == 1 && msg[0]->msg_style == PAM_PROMPT_ECHO_OFF) {
    *resp = malloc(sizeof(struct pam_response));
    assert(*resp);
    (*resp)->resp = strdup(response);
    (*resp)->resp_retcode = 0;
    return PAM_SUCCESS;
  }
  return PAM_CONV_ERR;
}

int pam_get_item(const pam_handle_t *pamh, int item_type, const void **item) {
  switch (item_type) {
    case PAM_SERVICE: {
      static const char *service = "google_authenticator_unittest";
      memcpy(item, &service, sizeof(&service));
      return PAM_SUCCESS;
    }
    case PAM_USER: {
      char *user = getenv("USER");
      memcpy(item, &user, sizeof(&user));
      return PAM_SUCCESS;
    }
    case PAM_CONV: {
      static struct pam_conv conv = { .conv = conversation }, *p_conv = &conv;
      memcpy(item, &p_conv, sizeof(p_conv));
      return PAM_SUCCESS;
    }
    default:
      return PAM_BAD_ITEM;
  }
}

int main(int argc, char *argv[]) {
  // Testing Base32 encoding
  puts("Checking base32 encoding");
  static const uint8_t dat[] = "Hello world...";
  uint8_t enc[((sizeof(dat) + 4)/5)*8 + 1];
  assert(base32_encode(dat, sizeof(dat), enc, sizeof(enc)) == sizeof(enc)-1);
  assert(!strcmp((char *)enc, "JBSWY3DPEB3W64TMMQXC4LQA"));
 
  puts("Checking base32 decoding");
  uint8_t dec[sizeof(dat)];
  assert(base32_decode(enc, dec, sizeof(dec)) == sizeof(dec));
  assert(!memcmp(dat, dec, sizeof(dat)));

  // Load the PAM module
  puts("Loading PAM module");
  void *pam_module = dlopen("./pam_google_authenticator_testing.so",
                            RTLD_LAZY | RTLD_GLOBAL);

  // Look up public symbols
  assert(pam_module != NULL);
  int (*pam_sm_open_session)(pam_handle_t *, int, int, const char **) =
      (int (*)(pam_handle_t *, int, int, const char **))
      dlsym(pam_module, "pam_sm_open_session");
  assert(pam_sm_open_session != NULL);

  // Look up private test-only API
  void (*set_secret_filename)(char *) =
      (void (*)(char *))dlsym(pam_module, "set_secret_filename");
  assert(set_secret_filename);
  void (*set_timestamp)(int ts) =
      (void (*)(int))dlsym(pam_module, "set_timestamp");
  assert(set_timestamp);

  // Create a secret file with a well-known test vector
  char fn[] = "/tmp/.google_authenticator_XXXXXX";
  int fd = mkstemp(fn);
  assert(fd >= 0);
  assert(write(fd,
               "2SH3V3GDW7ZNMGYE\n"
               "\" TOTP_AUTH", 28) == 28);
  close(fd);

  // Use the private test-only API to notify the PAM module where to find our
  // file
  set_secret_filename(fn);

  // Set the response that we should send back to the authentication module
  response = "50548";

  // Set the timestamp that this test vector needs
  set_timestamp(10000);

  // Check if we can log in when using a valid verification code
  puts("Testing successful login");
  assert(pam_sm_open_session(NULL, 0, 0, NULL) == PAM_SUCCESS);

  // Remove the temporarily created secret file
  unlink(fn);

  // Unload the PAM module
  dlclose(pam_module);

  puts("DONE");
  return 0;
}
