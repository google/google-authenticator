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
#include <fcntl.h>
#include <security/pam_modules.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "base32.h"
#include "hmac.h"

static char *response = "";

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
  puts("Testing base32 encoding");
  static const uint8_t dat[] = "Hello world...";
  uint8_t enc[((sizeof(dat) + 4)/5)*8 + 1];
  assert(base32_encode(dat, sizeof(dat), enc, sizeof(enc)) == sizeof(enc)-1);
  assert(!strcmp((char *)enc, "JBSWY3DPEB3W64TMMQXC4LQA"));
 
  puts("Testing base32 decoding");
  uint8_t dec[sizeof(dat)];
  assert(base32_decode(enc, dec, sizeof(dec)) == sizeof(dec));
  assert(!memcmp(dat, dec, sizeof(dat)));

  // Testing HMAC_SHA1
  puts("Testing HMAC_SHA1");
  uint8_t hmac[20];
  hmac_sha1((uint8_t *)"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C"
                       "\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19"
                       "\x1A\x1B\x1C\x1D\x1E\x1F !\"#$%&'()*+,-./0123456789:"
                       ";<=>?", 64,
            (uint8_t *)"Sample #1", 9,
            hmac, sizeof(hmac));
  assert(!memcmp(hmac,
                 (uint8_t []) { 0x4F, 0x4C, 0xA3, 0xD5, 0xD6, 0x8B, 0xA7, 0xCC,
                                0x0A, 0x12, 0x08, 0xC9, 0xC6, 0x1E, 0x9C, 0x5D,
                                0xA0, 0x40, 0x3C, 0x0A },
                 sizeof(hmac)));
  hmac_sha1((uint8_t *)"0123456789:;<=>?@ABC", 20,
            (uint8_t *)"Sample #2", 9,
            hmac, sizeof(hmac));
  assert(!memcmp(hmac,
                 (uint8_t []) { 0x09, 0x22, 0xD3, 0x40, 0x5F, 0xAA, 0x3D, 0x19,
                                0x4F, 0x82, 0xA4, 0x58, 0x30, 0x73, 0x7D, 0x5C,
                                0xC6, 0xC7, 0x5D, 0x24 },
                 sizeof(hmac)));
  hmac_sha1((uint8_t *)"PQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"
                       "\x7F\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8A"
                       "\x8B\x8C\x8D\x8E\x8F\x90\x91\x92\x93\x94\x95\x96"
                       "\x97\x98\x99\x9A\x9B\x9C\x9D\x9E\x9F\xA0\xA1\xA2"
                       "\xA3\xA4\xA5\xA6\xA7\xA8\xA9\xAA\xAB\xAC\xAD\xAE"
                       "\xAF\xB0\xB1\xB2\xB3", 100,
            (uint8_t *)"Sample #3", 9,
            hmac, sizeof(hmac));
  assert(!memcmp(hmac,
                 (uint8_t []) { 0xBC, 0xF4, 0x1E, 0xAB, 0x8B, 0xB2, 0xD8, 0x02,
                                0xF3, 0xD0, 0x5C, 0xAF, 0x7C, 0xB0, 0x92, 0xEC,
                                0xF8, 0xD1, 0xA3, 0xAA },
                 sizeof(hmac)));
  hmac_sha1((uint8_t *)"pqrstuvwxyz{|}~\x7F\x80\x81\x82\x83\x84\x85\x86\x87"
                       "\x88\x89\x8A\x8B\x8C\x8D\x8E\x8F\x90\x91\x92\x93\x94"
                       "\x95\x96\x97\x98\x99\x9A\x9B\x9C\x9D\x9E\x9F\xA0", 49,
            (uint8_t *)"Sample #4", 9,
            hmac, sizeof(hmac));
  assert(!memcmp(hmac,
                 (uint8_t []) { 0x9E, 0xA8, 0x86, 0xEF, 0xE2, 0x68, 0xDB, 0xEC,
                                0xCE, 0x42, 0x0C, 0x75, 0x24, 0xDF, 0x32, 0xE0,
                                0x75, 0x1A, 0x2A, 0x26 },
                 sizeof(hmac)));

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
  void (*set_time)(time_t t) =
      (void (*)(time_t))dlsym(pam_module, "set_time");
  assert(set_time);
  int (*compute_code)(uint8_t *, int, unsigned long) =
      (int (*)(uint8_t*, int, unsigned long))dlsym(pam_module, "compute_code");
  assert(compute_code);

  // Create a secret file with a well-known test vector
  char fn[] = "/tmp/.google_authenticator_XXXXXX";
  int fd = mkstemp(fn);
  assert(fd >= 0);
  static const uint8_t secret[] = "2SH3V3GDW7ZNMGYE";
  assert(write(fd, secret, sizeof(secret)-1) == sizeof(secret)-1);
  assert(write(fd, "\n\" TOTP_AUTH", 12) == 12);
  close(fd);
  uint8_t binary_secret[sizeof(secret)];
  size_t binary_secret_len = base32_decode(secret, binary_secret,
                                           sizeof(binary_secret));

  // Use the private test-only API to notify the PAM module where to find our
  // file
  set_secret_filename(fn);

  // Set the timestamp that this test vector needs
  set_time(10000*30);

  // Check if we can log in when using a valid verification code
  puts("Testing failed login attempt");
  assert(pam_sm_open_session(NULL, 0, 0, NULL) == PAM_SESSION_ERR);

  // Set the response that we should send back to the authentication module
  response = "50548";

  // Check if we can log in when using a valid verification code
  puts("Testing successful login");
  assert(pam_sm_open_session(NULL, 0, 0, NULL) == PAM_SUCCESS);

  // Test the WINDOW_SIZE option
  puts("Testing WINDOW_SIZE option");
  for (int *tm  = (int []){ 9998, 9999, 10001, 10002, 10000, -1 },
           *res = (int []){ PAM_SESSION_ERR, PAM_SUCCESS, PAM_SUCCESS,
                            PAM_SESSION_ERR, PAM_SUCCESS };
       *tm >= 0;) {
    set_time(*tm++ * 30);
    assert(pam_sm_open_session(NULL, 0, 0, NULL) == *res++);
  }
  assert(!chmod(fn, 0600));
  assert((fd = open(fn, O_APPEND | O_WRONLY)) >= 0);
  assert(write(fd, "\n\" WINDOW_SIZE 6\n", 17) == 17);
  close(fd);
  for (int *tm  = (int []){ 9996, 9997, 10002, 10003, 10000, -1 },
           *res = (int []){ PAM_SESSION_ERR, PAM_SUCCESS, PAM_SUCCESS,
                            PAM_SESSION_ERR, PAM_SUCCESS };
       *tm >= 0;) {
    set_time(*tm++ * 30);
    assert(pam_sm_open_session(NULL, 0, 0, NULL) == *res++);
  }

  // Test the DISALLOW_REUSE option
  puts("Testing DISALLOW_REUSE option");
  assert(pam_sm_open_session(NULL, 0, 0, NULL) == PAM_SUCCESS);
  assert(!chmod(fn, 0600));
  assert((fd = open(fn, O_APPEND | O_WRONLY)) >= 0);
  assert(write(fd, "\" DISALLOW_REUSE\n", 17) == 17);
  close(fd);
  assert(pam_sm_open_session(NULL, 0, 0, NULL) == PAM_SUCCESS);
  assert(pam_sm_open_session(NULL, 0, 0, NULL) == PAM_SESSION_ERR);

  // Test that DISALLOW_REUSE expires old entries from the re-use list
  char *old_response = response;
  for (int i = 10001; i < 10008; ++i) {
    set_time(i * 30);
    char buf[7];
    response = buf;
    sprintf(response, "%d", compute_code(binary_secret, binary_secret_len, i));
    assert(pam_sm_open_session(NULL, 0, 0, NULL) == PAM_SUCCESS);
  }
  set_time(10000 * 30);
  response = old_response;
  assert((fd = open(fn, O_RDONLY)) >= 0);
  char state_file_buf[4096] = { 0 };
  assert(read(fd, state_file_buf, sizeof(state_file_buf)-1) > 0);
  close(fd);
  const char *disallow = strstr(state_file_buf, "\" DISALLOW_REUSE ");
  assert(disallow);
  assert(!memcmp(disallow + 17, "10002 10003 10004 10005 10006 10007\n", 36));

  // Test the RATE_LIMIT option
  puts("Testing RATE_LIMIT option");
  assert(!chmod(fn, 0600));
  assert((fd = open(fn, O_APPEND | O_WRONLY)) >= 0);
  assert(write(fd, "\" RATE_LIMIT 2 90\n", 18) == 18);
  close(fd);
  for (int *tm  = (int []){ 20000, 20001, 20002, 20005, -1 },
           *res = (int []){ PAM_SUCCESS, PAM_SUCCESS, PAM_SESSION_ERR,
                            PAM_SUCCESS, -1 };
       *tm >= 0;) {
    set_time(*tm * 30);
    char buf[7];
    response = buf;
    sprintf(response, "%d", compute_code(binary_secret,
                                         binary_secret_len,
                                         *tm++));
    assert(pam_sm_open_session(NULL, 0, 0, NULL) == *res++);
  }
  set_time(10000 * 30);
  response = old_response;
  assert((fd = open(fn, O_RDONLY)) >= 0);
  memset(state_file_buf, 0, sizeof(state_file_buf));
  assert(read(fd, state_file_buf, sizeof(state_file_buf)-1) > 0);
  close(fd);
  const char *rate_limit = strstr(state_file_buf, "\" RATE_LIMIT ");
  assert(rate_limit);
  assert(!memcmp(rate_limit + 13, "2 90 600060 600150\n", 19));

  // Test scratch codes
  puts("Testing scratch codes");
  response = "12345678";
  assert(pam_sm_open_session(NULL, 0, 0, NULL) == PAM_SESSION_ERR);
  assert(!chmod(fn, 0600));
  assert((fd = open(fn, O_APPEND | O_WRONLY)) >= 0);
  assert(write(fd, "12345678\n", 9) == 9);
  close(fd);
  assert(pam_sm_open_session(NULL, 0, 0, NULL) == PAM_SUCCESS);
  assert(pam_sm_open_session(NULL, 0, 0, NULL) == PAM_SESSION_ERR);

  // Remove the temporarily created secret file
  unlink(fn);

  // Unload the PAM module
  dlclose(pam_module);

  puts("DONE");
  return 0;
}
