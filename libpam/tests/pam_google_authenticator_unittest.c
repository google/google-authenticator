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
#include "config.h"

#include <assert.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "../src/base32.h"
#include "../src/hmac.h"

#if !defined(PAM_BAD_ITEM)
// FreeBSD does not know about PAM_BAD_ITEM. And PAM_SYMBOL_ERR is an "enum",
// we can't test for it at compile-time.
#define PAM_BAD_ITEM PAM_SYMBOL_ERR
#endif

static PAM_CONST char pw[] = "0123456789";
static char *response = "";
static void *pam_module;
static enum { TWO_PROMPTS, COMBINED_PASSWORD, COMBINED_PROMPT } conv_mode;
static int num_prompts_shown = 0;

static int conversation(int num_msg, PAM_CONST struct pam_message **msg,
                        struct pam_response **resp, void *appdata_ptr) {
  // Keep track of how often the conversation callback is executed.
  ++num_prompts_shown;
  if (conv_mode == COMBINED_PASSWORD) {
    return PAM_CONV_ERR;
  }
  if (num_msg == 1 && msg[0]->msg_style == PAM_PROMPT_ECHO_OFF) {
    *resp = malloc(sizeof(struct pam_response));
    assert(*resp);
    (*resp)->resp = conv_mode == TWO_PROMPTS
      ? strdup(response)
      : strcat(strcpy(malloc(sizeof(pw) + strlen(response)), pw), response);
    (*resp)->resp_retcode = 0;
    return PAM_SUCCESS;
  }
  return PAM_CONV_ERR;
}

int pam_get_user(pam_handle_t *pamh, PAM_CONST char **user,
                 PAM_CONST char *prompt)
  __attribute__((visibility("default")));
int pam_get_user(pam_handle_t *pamh, PAM_CONST char **user,
                 PAM_CONST char *prompt) {
  return pam_get_item(pamh, PAM_USER, (void *)user);
}

int pam_get_item(const pam_handle_t *pamh, int item_type,
                 PAM_CONST void **item)
  __attribute__((visibility("default")));
int pam_get_item(const pam_handle_t *pamh, int item_type,
                 PAM_CONST void **item) {
  switch (item_type) {
    case PAM_SERVICE: {
      static const char *service = "google_authenticator_unittest";
      *item = service;
      return PAM_SUCCESS;
    }
    case PAM_USER: {
      char *user = getenv("USER");
      *item = user;
      return PAM_SUCCESS;
    }
    case PAM_CONV: {
      static struct pam_conv conv = { .conv = conversation }, *p_conv = &conv;
      *item = p_conv;
      return PAM_SUCCESS;
    }
    case PAM_AUTHTOK: {
      static char *authtok = NULL;
      if (conv_mode == COMBINED_PASSWORD) {
        authtok = realloc(authtok, sizeof(pw) + strlen(response));
        *item = strcat(strcpy(authtok, pw), response);
      } else {
        *item = pw;
      }
      return PAM_SUCCESS;
    }
    default:
      return PAM_BAD_ITEM;
  }
}

int pam_set_item(pam_handle_t *pamh, int item_type,
                 const void *item)
  __attribute__((visibility("default")));
int pam_set_item(pam_handle_t *pamh, int item_type,
                 const void *item) {
  switch (item_type) {
    case PAM_AUTHTOK:
      if (strcmp((char *)item, pw)) {
        return PAM_BAD_ITEM;
      }
      return PAM_SUCCESS;
    default:
      return PAM_BAD_ITEM;
  }
}

// Return the last line of the error message.
static const char *get_error_msg(void) {
  const char *(*get_error_msg)(void) =
    (const char *(*)(void))dlsym(pam_module, "get_error_msg");
  const char* msg = get_error_msg ? get_error_msg() : "";
  const char* p = strrchr(msg, '\n');
  if (p) {
    msg = p+1;
  }
  return msg;
}

static void print_diagnostics(int signo) {
  if (*get_error_msg()) {
    fprintf(stderr, "%s\n", get_error_msg());
  }
  _exit(1);
}

#define verify_prompts_shown(expected_prompts_shown) do { \
  assert(num_prompts_shown == (expected_prompts_shown)); \
  num_prompts_shown = 0; /* Reset for the next count. */ \
} while(0)

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
  pam_module = dlopen("./.libs/libpam_google_authenticator_testing.so",
                      RTLD_NOW | RTLD_GLOBAL);
  if (pam_module == NULL) {
    fprintf(stderr, "dlopen(): %s\n", dlerror());
    exit(1);
  }
  signal(SIGABRT, print_diagnostics);

  // Look up public symbols
  int (*pam_sm_authenticate)(pam_handle_t *, int, int, const char **) =
      (int (*)(pam_handle_t *, int, int, const char **))
      dlsym(pam_module, "pam_sm_authenticate");
  assert(pam_sm_authenticate != NULL);

  // Look up private test-only API
  void (*set_time)(time_t t) =
      (void (*)(time_t))dlsym(pam_module, "set_time");
  assert(set_time);
  int (*compute_code)(uint8_t *, int, unsigned long) =
      (int (*)(uint8_t*, int, unsigned long))dlsym(pam_module, "compute_code");
  assert(compute_code);

  for (int otp_mode = 0; otp_mode < 8; ++otp_mode) {
    // Create a secret file with a well-known test vector
    char fn[] = "/tmp/.google_authenticator_XXXXXX";
    mode_t orig_umask = umask(S_IRWXG|S_IRWXO); // Only for the current user.
    int fd = mkstemp(fn);
    (void)umask(orig_umask);
    assert(fd >= 0);
    static const uint8_t secret[] = "2SH3V3GDW7ZNMGYE";
    assert(write(fd, secret, sizeof(secret)-1) == sizeof(secret)-1);
    assert(write(fd, "\n\" TOTP_AUTH", 12) == 12);
    close(fd);
    uint8_t binary_secret[sizeof(secret)];
    size_t binary_secret_len = base32_decode(secret, binary_secret,
                                             sizeof(binary_secret));

    // Set up test argc/argv parameters to let the PAM module know where to
    // find our secret file
    const char *targv[] = { malloc(strlen(fn) + 8), NULL, NULL, NULL, NULL };
    strcat(strcpy((char *)targv[0], "secret="), fn);
    int targc;
    int expected_good_prompts_shown;
    int expected_bad_prompts_shown;

    switch (otp_mode) {
    case 0:
      puts("\nRunning tests, querying for verification code");
      conv_mode = TWO_PROMPTS;
      targc = 1;
      expected_good_prompts_shown = expected_bad_prompts_shown = 1;
      break;
    case 1:
      puts("\nRunning tests, querying for verification code, "
           "forwarding system pass");
      conv_mode = COMBINED_PROMPT;
      targv[1] = strdup("forward_pass");
      targc = 2;
      expected_good_prompts_shown = expected_bad_prompts_shown = 1;
      break;
    case 2:
      puts("\nRunning tests with use_first_pass");
      conv_mode = COMBINED_PASSWORD;
      targv[1] = strdup("use_first_pass");
      targc = 2;
      expected_good_prompts_shown = expected_bad_prompts_shown = 0;
      break;
    case 3:
      puts("\nRunning tests with use_first_pass, forwarding system pass");
      conv_mode = COMBINED_PASSWORD;
      targv[1] = strdup("use_first_pass");
      targv[2] = strdup("forward_pass");
      targc = 3;
      expected_good_prompts_shown = expected_bad_prompts_shown = 0;
      break;
    case 4:
      puts("\nRunning tests with try_first_pass, combining codes");
      conv_mode = COMBINED_PASSWORD;
      targv[1] = strdup("try_first_pass");
      targc = 2;
      expected_good_prompts_shown = 0;
      expected_bad_prompts_shown = 2;
      break;
    case 5:
      puts("\nRunning tests with try_first_pass, combining codes, "
           "forwarding system pass");
      conv_mode = COMBINED_PASSWORD;
      targv[1] = strdup("try_first_pass");
      targv[2] = strdup("forward_pass");
      targc = 3;
      expected_good_prompts_shown = 0;
      expected_bad_prompts_shown = 2;
      break;
    case 6:
      puts("\nRunning tests with try_first_pass, querying for codes");
      conv_mode = TWO_PROMPTS;
      targv[1] = strdup("try_first_pass");
      targc = 2;
      expected_good_prompts_shown = expected_bad_prompts_shown = 1;
      break;
    default:
      assert(otp_mode == 7);
      puts("\nRunning tests with try_first_pass, querying for codes, "
           "forwarding system pass");
      conv_mode = COMBINED_PROMPT;
      targv[1] = strdup("try_first_pass");
      targv[2] = strdup("forward_pass");
      targc = 3;
      expected_good_prompts_shown = expected_bad_prompts_shown = 1;
      break;
    }

    // Make sure num_prompts_shown is still 0.
    verify_prompts_shown(0);

    // Set the timestamp that this test vector needs
    set_time(10000*30);

    response = "123456";

    // Check if we can log in when using an invalid verification code
    puts("Testing failed login attempt");
    assert(pam_sm_authenticate(NULL, 0, targc, targv) == PAM_AUTH_ERR);
    verify_prompts_shown(expected_bad_prompts_shown);

    // Check required number of digits
    if (conv_mode == TWO_PROMPTS) {
      puts("Testing required number of digits");
      response = "50548";
      assert(pam_sm_authenticate(NULL, 0, targc, targv) == PAM_AUTH_ERR);
      verify_prompts_shown(expected_bad_prompts_shown);
      response = "0050548";
      assert(pam_sm_authenticate(NULL, 0, targc, targv) == PAM_AUTH_ERR);
      verify_prompts_shown(expected_bad_prompts_shown);
      response = "00050548";
      assert(pam_sm_authenticate(NULL, 0, targc, targv) == PAM_AUTH_ERR);
      verify_prompts_shown(expected_bad_prompts_shown);
    }

    // Test a blank response
    puts("Testing a blank response");
    response = "";
    assert(pam_sm_authenticate(NULL, 0, targc, targv) == PAM_AUTH_ERR);
    verify_prompts_shown(expected_bad_prompts_shown);

    // Set the response that we should send back to the authentication module
    response = "050548";

    // Test handling of missing state files
    puts("Test handling of missing state files");
    const char *old_secret = targv[0];
    targv[0] = "secret=/NOSUCHFILE";
    assert(pam_sm_authenticate(NULL, 0, targc, targv) == PAM_AUTH_ERR);
    verify_prompts_shown(0);
    targv[targc++] = "nullok";
    targv[targc] = NULL;
    assert(pam_sm_authenticate(NULL, 0, targc, targv) == PAM_SUCCESS);
    verify_prompts_shown(0);
    targv[--targc] = NULL;
    targv[0] = old_secret;

    // Check if we can log in when using a valid verification code
    puts("Testing successful login");
    assert(pam_sm_authenticate(NULL, 0, targc, targv) == PAM_SUCCESS);
    verify_prompts_shown(expected_good_prompts_shown);

    // Test the STEP_SIZE option
    puts("Testing STEP_SIZE option");
    assert(!chmod(fn, 0600));
    assert((fd = open(fn, O_APPEND | O_WRONLY)) >= 0);
    assert(write(fd, "\n\" STEP_SIZE 60\n", 16) == 16);
    close(fd);
    for (int *tm  = (int []){ 9998, 9999, 10001, 10002, 10000, -1 },
             *res = (int []){ PAM_AUTH_ERR, PAM_SUCCESS, PAM_SUCCESS,
                              PAM_AUTH_ERR, PAM_SUCCESS };
         *tm >= 0;) {
      set_time(*tm++ * 60);
      assert(pam_sm_authenticate(NULL, 0, targc, targv) == *res++);
      verify_prompts_shown(expected_good_prompts_shown);
    }

    // Reset secret file after step size testing.
    assert(!chmod(fn, 0600));
    assert((fd = open(fn, O_TRUNC | O_WRONLY)) >= 0);
    assert(write(fd, secret, sizeof(secret)-1) == sizeof(secret)-1);
    assert(write(fd, "\n\" TOTP_AUTH", 12) == 12);
    close(fd);

    // Test the WINDOW_SIZE option
    puts("Testing WINDOW_SIZE option");
    for (int *tm  = (int []){ 9998, 9999, 10001, 10002, 10000, -1 },
             *res = (int []){ PAM_AUTH_ERR, PAM_SUCCESS, PAM_SUCCESS,
                              PAM_AUTH_ERR, PAM_SUCCESS };
         *tm >= 0;) {
      set_time(*tm++ * 30);
      assert(pam_sm_authenticate(NULL, 0, targc, targv) == *res++);
      verify_prompts_shown(expected_good_prompts_shown);
    }
    assert(!chmod(fn, 0600));
    assert((fd = open(fn, O_APPEND | O_WRONLY)) >= 0);
    assert(write(fd, "\n\" WINDOW_SIZE 6\n", 17) == 17);
    close(fd);
    for (int *tm  = (int []){ 9996, 9997, 10002, 10003, 10000, -1 },
             *res = (int []){ PAM_AUTH_ERR, PAM_SUCCESS, PAM_SUCCESS,
                              PAM_AUTH_ERR, PAM_SUCCESS };
         *tm >= 0;) {
      set_time(*tm++ * 30);
      assert(pam_sm_authenticate(NULL, 0, targc, targv) == *res++);
      verify_prompts_shown(expected_good_prompts_shown);
    }

    // Test the DISALLOW_REUSE option
    puts("Testing DISALLOW_REUSE option");
    assert(pam_sm_authenticate(NULL, 0, targc, targv) == PAM_SUCCESS);
    verify_prompts_shown(expected_good_prompts_shown);
    assert(!chmod(fn, 0600));
    assert((fd = open(fn, O_APPEND | O_WRONLY)) >= 0);
    assert(write(fd, "\" DISALLOW_REUSE\n", 17) == 17);
    close(fd);
    assert(pam_sm_authenticate(NULL, 0, targc, targv) == PAM_SUCCESS);
    verify_prompts_shown(expected_good_prompts_shown);
    assert(pam_sm_authenticate(NULL, 0, targc, targv) == PAM_AUTH_ERR);
    verify_prompts_shown(expected_good_prompts_shown);

    // Test that DISALLOW_REUSE expires old entries from the re-use list
    char *old_response = response;
    for (int i = 10001; i < 10008; ++i) {
      set_time(i * 30);
      char buf[7];
      response = buf;
      sprintf(response, "%06d", compute_code(binary_secret,
                                             binary_secret_len, i));
      assert(pam_sm_authenticate(NULL, 0, targc, targv) == PAM_SUCCESS);
      verify_prompts_shown(expected_good_prompts_shown);
    }
    set_time(10000 * 30);
    response = old_response;
    assert((fd = open(fn, O_RDONLY)) >= 0);
    char state_file_buf[4096] = { 0 };
    assert(read(fd, state_file_buf, sizeof(state_file_buf)-1) > 0);
    close(fd);
    const char *disallow = strstr(state_file_buf, "\" DISALLOW_REUSE ");
    assert(disallow);
    assert(!memcmp(disallow + 17,
                   "10002 10003 10004 10005 10006 10007\n", 36));

    // Test the RATE_LIMIT option
    puts("Testing RATE_LIMIT option");
    assert(!chmod(fn, 0600));
    assert((fd = open(fn, O_APPEND | O_WRONLY)) >= 0);
    assert(write(fd, "\" RATE_LIMIT 4 120\n", 19) == 19);
    close(fd);
    for (int *tm  = (int []){ 20000, 20001, 20002, 20003, 20004, 20006, -1 },
             *res = (int []){ PAM_SUCCESS, PAM_SUCCESS, PAM_SUCCESS,
                              PAM_SUCCESS, PAM_AUTH_ERR, PAM_SUCCESS, -1 };
         *tm >= 0;) {
      set_time(*tm * 30);
      char buf[7];
      response = buf;
      sprintf(response, "%06d",
              compute_code(binary_secret, binary_secret_len, *tm++));
      assert(pam_sm_authenticate(NULL, 0, targc, targv) == *res);
      verify_prompts_shown(
          *res != PAM_SUCCESS ? 0 : expected_good_prompts_shown);
      ++res;
    }
    set_time(10000 * 30);
    response = old_response;
    assert(!chmod(fn, 0600));
    assert((fd = open(fn, O_RDWR)) >= 0);
    memset(state_file_buf, 0, sizeof(state_file_buf));
    assert(read(fd, state_file_buf, sizeof(state_file_buf)-1) > 0);
    const char *rate_limit = strstr(state_file_buf, "\" RATE_LIMIT ");
    assert(rate_limit);
    assert(!memcmp(rate_limit + 13,
                   "4 120 600060 600090 600120 600180\n", 35));

    // Test trailing space in RATE_LIMIT. This is considered a file format
    // error.
    char *eol = strchr(rate_limit, '\n');
    *eol = ' ';
    assert(!lseek(fd, 0, SEEK_SET));
    assert(write(fd, state_file_buf, strlen(state_file_buf)) ==
           strlen(state_file_buf));
    close(fd);
    assert(pam_sm_authenticate(NULL, 0, targc, targv) == PAM_AUTH_ERR);
    verify_prompts_shown(0);
    assert(!strncmp(get_error_msg(),
                    "Invalid list of timestamps in RATE_LIMIT", 40));
    *eol = '\n';
    assert(!chmod(fn, 0600));
    assert((fd = open(fn, O_WRONLY)) >= 0);
    assert(write(fd, state_file_buf, strlen(state_file_buf)) ==
           strlen(state_file_buf));
    close(fd);

    // Test TIME_SKEW option
    puts("Testing TIME_SKEW");
    for (int i = 0; i < 4; ++i) {
      set_time((12000 + i)*30);
      char buf[7];
      response = buf;
      sprintf(response, "%06d",
              compute_code(binary_secret, binary_secret_len, 11000 + i));
      assert(pam_sm_authenticate(NULL, 0, targc, targv) ==
             (i >= 2 ? PAM_SUCCESS : PAM_AUTH_ERR));
      verify_prompts_shown(expected_good_prompts_shown);
    }
    set_time(12010 * 30);
    char buf[7];
    response = buf;
    sprintf(response, "%06d", compute_code(binary_secret,
                                           binary_secret_len, 11010));
    assert(pam_sm_authenticate(NULL, 0, 1,
                               (const char *[]){ "noskewadj", 0 }) ==
           PAM_AUTH_ERR);
    verify_prompts_shown(0);
    set_time(10000*30);

    // Test scratch codes
    puts("Testing scratch codes");
    response = "12345678";
    assert(pam_sm_authenticate(NULL, 0, targc, targv) == PAM_AUTH_ERR);
    verify_prompts_shown(expected_bad_prompts_shown);
    assert(!chmod(fn, 0600));
    assert((fd = open(fn, O_APPEND | O_WRONLY)) >= 0);
    assert(write(fd, "12345678\n", 9) == 9);
    close(fd);
    assert(pam_sm_authenticate(NULL, 0, targc, targv) == PAM_SUCCESS);
    verify_prompts_shown(expected_good_prompts_shown);
    assert(pam_sm_authenticate(NULL, 0, targc, targv) == PAM_AUTH_ERR);
    verify_prompts_shown(expected_bad_prompts_shown);

    // Set up secret file for counter-based codes.
    assert(!chmod(fn, 0600));
    assert((fd = open(fn, O_TRUNC | O_WRONLY)) >= 0);
    assert(write(fd, secret, sizeof(secret)-1) == sizeof(secret)-1);
    assert(write(fd, "\n\" HOTP_COUNTER 1\n", 18) == 18);
    close(fd);

    response = "293240";

    // Check if we can log in when using a valid verification code
    puts("Testing successful counter-based login");
    assert(pam_sm_authenticate(NULL, 0, targc, targv) == PAM_SUCCESS);
    verify_prompts_shown(expected_good_prompts_shown);

    // Verify that the hotp counter incremented
    assert((fd = open(fn, O_RDONLY)) >= 0);
    memset(state_file_buf, 0, sizeof(state_file_buf));
    assert(read(fd, state_file_buf, sizeof(state_file_buf)-1) > 0);
    close(fd);
    const char *hotp_counter = strstr(state_file_buf, "\" HOTP_COUNTER ");
    assert(hotp_counter);
    assert(!memcmp(hotp_counter + 15, "2\n", 2));

    // Check if we can log in when using an invalid verification code
    // (including the same code a second time)
    puts("Testing failed counter-based login attempt");
    assert(pam_sm_authenticate(NULL, 0, targc, targv) == PAM_AUTH_ERR);
    verify_prompts_shown(expected_bad_prompts_shown);

    // Verify that the hotp counter incremented
    assert((fd = open(fn, O_RDONLY)) >= 0);
    memset(state_file_buf, 0, sizeof(state_file_buf));
    assert(read(fd, state_file_buf, sizeof(state_file_buf)-1) > 0);
    close(fd);
    hotp_counter = strstr(state_file_buf, "\" HOTP_COUNTER ");
    assert(hotp_counter);
    assert(!memcmp(hotp_counter + 15, "3\n", 2));

    response = "932068";

    // Check if we can log in using a future valid verification code (using
    // default window_size of 3)
    puts("Testing successful future counter-based login");
    assert(pam_sm_authenticate(NULL, 0, targc, targv) == PAM_SUCCESS);
    verify_prompts_shown(expected_good_prompts_shown);

    // Verify that the hotp counter incremented
    assert((fd = open(fn, O_RDONLY)) >= 0);
    memset(state_file_buf, 0, sizeof(state_file_buf));
    assert(read(fd, state_file_buf, sizeof(state_file_buf)-1) > 0);
    close(fd);
    hotp_counter = strstr(state_file_buf, "\" HOTP_COUNTER ");
    assert(hotp_counter);
    assert(!memcmp(hotp_counter + 15, "6\n", 2));

    // Remove the temporarily created secret file
    unlink(fn);

    // Release memory for the test arguments
    for (int i = 0; i < targc; ++i) {
      free((void *)targv[i]);
    }
  }

  // Unload the PAM module
  dlclose(pam_module);

  puts("DONE");
  return 0;
}
