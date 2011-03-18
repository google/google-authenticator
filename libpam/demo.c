// Demo wrapper for the PAM module. This is part of the Google Authenticator
// project.
//
// Copyright 2011 Google Inc.
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
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if !defined(PAM_BAD_ITEM)
// FreeBSD does not know about PAM_BAD_ITEM. And PAM_SYMBOL_ERR is an "enum",
// we can't test for it at compile-time.
#define PAM_BAD_ITEM PAM_SYMBOL_ERR
#endif

static void *pam_module;

static int conversation(int num_msg, const struct pam_message **msg,
                        struct pam_response **resp, void *appdata_ptr) {
  if (num_msg == 1 && msg[0]->msg_style == PAM_PROMPT_ECHO_OFF) {
    printf("%s ", msg[0]->msg);
    *resp = malloc(sizeof(struct pam_response));
    assert(*resp);
    (*resp)->resp = calloc(1024, 0);
    assert(fgets((*resp)->resp, 1024, stdin));
    char *ptr = strrchr((*resp)->resp, '\n');
    if (ptr) {
      *ptr = '\000';
    }
    (*resp)->resp_retcode = 0;
    return PAM_SUCCESS;
  }
  return PAM_CONV_ERR;
}

int pam_get_item(const pam_handle_t *pamh, int item_type, const void **item) {
  switch (item_type) {
    case PAM_SERVICE: {
      static const char *service = "google_authenticator_demo";
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

static void print_diagnostics(int signo) {
  const char *(*get_error_msg)(void) =
    (const char *(*)(void))dlsym(pam_module, "get_error_msg");
  if (get_error_msg && *get_error_msg()) {
    fprintf(stderr, "%s\n", get_error_msg());
  }
  _exit(1);
}

int main(int argc, char *argv[]) {
  // Load the PAM module
  puts("Loading PAM module");
  pam_module = dlopen("./pam_google_authenticator_demo.so",
                      RTLD_LAZY | RTLD_GLOBAL);
  assert(pam_module != NULL);
  signal(SIGABRT, print_diagnostics);

  // Look up public symbols
  int (*pam_sm_open_session)(pam_handle_t *, int, int, const char **) =
      (int (*)(pam_handle_t *, int, int, const char **))
      dlsym(pam_module, "pam_sm_open_session");
  assert(pam_sm_open_session != NULL);

  if (pam_sm_open_session(NULL, 0, argc-1, (const char **)argv+1)
      != PAM_SUCCESS) {
    fprintf(stderr, "Login failed\n");
    abort();
  }
  puts("Success");

  return 0;
}
