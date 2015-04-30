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
#include <fcntl.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <termios.h>
#include <unistd.h>

#if !defined(PAM_BAD_ITEM)
// FreeBSD does not know about PAM_BAD_ITEM. And PAM_SYMBOL_ERR is an "enum",
// we can't test for it at compile-time.
#define PAM_BAD_ITEM PAM_SYMBOL_ERR
#endif

static struct termios old_termios;
static int jmpbuf_valid;
static sigjmp_buf jmpbuf;

static int conversation(int num_msg, const struct pam_message **msg,
                        struct pam_response **resp, void *appdata_ptr) {
  if (num_msg == 1 &&
      (msg[0]->msg_style == PAM_PROMPT_ECHO_OFF ||
       msg[0]->msg_style == PAM_PROMPT_ECHO_ON)) {
    *resp = malloc(sizeof(struct pam_response));
    assert(*resp);
    (*resp)->resp = calloc(1024, 0);
    struct termios termios = old_termios;
    if (msg[0]->msg_style == PAM_PROMPT_ECHO_OFF) {
      termios.c_lflag &= ~(ECHO|ECHONL);
    }
    sigsetjmp(jmpbuf, 1);
    jmpbuf_valid = 1;
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGTSTP);
    assert(!sigprocmask(SIG_UNBLOCK, &mask, NULL));
    printf("%s ", msg[0]->msg);
    assert(!tcsetattr(0, TCSAFLUSH, &termios));
    assert(fgets((*resp)->resp, 1024, stdin));
    assert(!tcsetattr(0, TCSAFLUSH, &old_termios));
    puts("");
    assert(!sigprocmask(SIG_BLOCK, &mask, NULL));
    jmpbuf_valid = 0;
    char *ptr = strrchr((*resp)->resp, '\n');
    if (ptr) {
      *ptr = '\000';
    }
    (*resp)->resp_retcode = 0;
    return PAM_SUCCESS;
  }
  return PAM_CONV_ERR;
}

#ifdef sun
#define PAM_CONST
#else
#define PAM_CONST const
#endif
int pam_get_item(const pam_handle_t *pamh, int item_type,
                 PAM_CONST void **item) {
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

int pam_set_item(pam_handle_t *pamh, int item_type,
                 PAM_CONST void *item) {
  switch (item_type) {
    case PAM_AUTHTOK:
      return PAM_SUCCESS;
    default:
      return PAM_BAD_ITEM;
  }
}

static void print_diagnostics(int signo) {
  extern const char *get_error_msg(void);
  assert(!tcsetattr(0, TCSAFLUSH, &old_termios));
  fprintf(stderr, "%s\n", get_error_msg());
  _exit(1);
}

static void reset_console(int signo) {
  assert(!tcsetattr(0, TCSAFLUSH, &old_termios));
  puts("");
  _exit(1);
}

static void stop(int signo) {
  assert(!tcsetattr(0, TCSAFLUSH, &old_termios));
  puts("");
  raise(SIGSTOP);
}

static void cont(int signo) {
  if (jmpbuf_valid) {
    siglongjmp(jmpbuf, 0);
  }
}

int main(int argc, char *argv[]) {
  extern int pam_sm_authenticate(pam_handle_t *, int, int, const char **);

  // Try to redirect stdio to /dev/tty
  int fd = open("/dev/tty", O_RDWR);
  if (fd >= 0) {
    dup2(fd, 0);
    dup2(fd, 1);
    dup2(fd, 2);
    close(fd);
  }

  // Disable core files
  assert(!setrlimit(RLIMIT_CORE, (struct rlimit []){ { 0, 0 } }));

  // Set up error and job control handlers
  assert(!tcgetattr(0, &old_termios));
  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGTSTP);
  assert(!sigprocmask(SIG_BLOCK, &mask, NULL));
  assert(!signal(SIGABRT, print_diagnostics));
  assert(!signal(SIGINT, reset_console));
  assert(!signal(SIGTSTP, stop));
  assert(!signal(SIGCONT, cont));

  // Attempt login
  if (pam_sm_authenticate(NULL, 0, argc-1, (const char **)argv+1)
      != PAM_SUCCESS) {
    fprintf(stderr, "Login failed\n");
    abort();
  }

  return 0;
}
