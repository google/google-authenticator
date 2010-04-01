// PAM module for two-factor authentication.
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

#define _GNU_SOURCE
#include <fcntl.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fsuid.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#define PAM_SM_AUTH
#define PAM_SM_SESSION
#include <security/pam_modules.h>

#include "base32.h"
#include "hmac.h"
#include "sha1.h"

#define MODULE_NAME "pam_google_authenticator"
#define SECRET      "/.google_authenticator"

static void log_message(int priority, pam_handle_t *pamh,
                        const char *format, ...) {
  char *service = NULL;
  if (pamh)
    pam_get_item(pamh, PAM_SERVICE, (void *)&service);
  if (!service)
    service = "";

  char logname[80];
  snprintf(logname, sizeof(logname), "%s(" MODULE_NAME ")", service);

  va_list args;
  va_start(args, format);
  openlog(logname, LOG_CONS | LOG_PID, LOG_AUTHPRIV);
  vsyslog(priority, format, args);
  va_end(args);

  closelog();
}

static int converse(pam_handle_t *pamh, int nargs,
                    const struct pam_message **message,
                    struct pam_response **response) {
  struct pam_conv *conv;
  int retval = pam_get_item(pamh, PAM_CONV, (void *)&conv);
  if (retval != PAM_SUCCESS) {
    return retval;
  }
  return conv->conv(nargs, message, response, conv->appdata_ptr);
}

static const char *get_user_name(pam_handle_t *pamh) {
  // Obtain the user's name
  const char *username;
  if (pam_get_item(pamh, PAM_USER, (void *)&username) != PAM_SUCCESS ||
      !username || !*username) {
    log_message(LOG_ERR, pamh,
                "No user name available when checking verification code");
    return NULL;
  }
  return username;
}

#ifdef TESTING
static char *secret_file_name;
void set_secret_filename(char *fn) {
  secret_file_name = fn;
}

static char *get_secret_filename(pam_handle_t *pamh, const char *username,
                                 int *uid) {
  *uid = getuid();
  return strdup(secret_file_name);
}
#else
static char *get_secret_filename(pam_handle_t *pamh, const char *username,
                                 int *uid) {
  // Obtain the user's home directory
  struct passwd pwbuf, *pw;
  #ifdef _SC_GETPW_R_SIZE_MAX
  int len = sysconf(_SC_GETPW_R_SIZE_MAX);
  if (len <= 0) {
    len = 4096;
  }
  #else
  int len = 4096;
  #endif
  char *buf = malloc(len);
  char *secret_filename = NULL;
  *uid = -1;
  if (buf == NULL ||
      getpwnam_r(username, &pwbuf, buf, len, &pw) ||
      !pw ||
      !pw->pw_dir ||
      *pw->pw_dir != '/' ||
      !(secret_filename = malloc(strlen(pw->pw_dir) + strlen(SECRET) + 1))) {
    log_message(LOG_ERR, pamh, "Failed to find home directory for user \"%s\"",
                username);
    free(buf);
    free(secret_filename);
    return NULL;
  }
  free(buf);
  strcat(strcpy(secret_filename, pw->pw_dir), SECRET);
  *uid = pw->pw_uid;
  return secret_filename;
}
#endif

static int drop_privileges(pam_handle_t *pamh, const char *username, int uid) {
  // Try to become the new user. This might be necessary for NFS mounted home
  // directories.
  int old_uid = setfsuid(uid);
  if (uid != setfsuid(uid)) {
    log_message(LOG_ERR, pamh, "Failed to change user id to \"%s\"", username);
    setfsuid(old_uid);
    return -1;
  }
  return old_uid;
}

static int open_secret_file(pam_handle_t *pamh, const char *secret_filename,
                            const char *username, int uid, off_t *size,
                            time_t *mtime) {
  // Try to open "~/.google_authenticator"
  *size = 0;
  *mtime = 0;
  int fd = open(secret_filename, O_RDONLY);
  struct stat sb;
  if (fd < 0 ||
      fstat(fd, &sb) < 0) {
    log_message(LOG_ERR, pamh, "Failed to read \"%s\"", secret_filename);
 error:
    if (fd >= 0) {
      close(fd);
    }
    return -1;
  }

  // Check permissions on "~/.google_authenticator"
  if ((sb.st_mode & 03577) != 0400 ||
      !S_ISREG(sb.st_mode) ||
      sb.st_uid != (uid_t)uid) {
    log_message(LOG_ERR, pamh,
                "Secret file \"%s\" must only be accessible by \"%s\"",
                secret_filename, username);
    goto error;
  }

  // Sanity check for file length
  if (sb.st_size < 1 || sb.st_size > 1024) {
    log_message(LOG_ERR, pamh,
                "Invalid file size for \"%s\"", secret_filename);
    goto error;
  }

  *size = sb.st_size;
  *mtime = sb.st_mtime;
  return fd;
}

static char *read_file_contents(pam_handle_t *pamh,
                                const char *secret_filename, int fd,
                                off_t filesize) {
  // Read file contents
  char *buf = malloc(filesize + 1);
  if (!buf ||
      read(fd, buf, filesize) != filesize) {
    log_message(LOG_ERR, pamh, "Could not read \"%s\"", secret_filename);
 error:
    if (buf) {
      memset(buf, 0, filesize);
      free(buf);
    }
    return NULL;
  }

  // The rest of the code assumes that there are no NUL bytes in the file.
  if (memchr(buf, 0, filesize)) {
    log_message(LOG_ERR, pamh, "Invalid file contents in \"%s\"",
                secret_filename);
    goto error;
  }

  // Terminate the buffer with a NUL byte.
  buf[filesize] = '\000';

  return buf;
}

static int is_totp(const char *buf) {
  return !!strstr(buf, "\" TOTP_AUTH");
}

static int write_file_contents(pam_handle_t *pamh, const char *secret_filename,
                               off_t old_size, time_t old_mtime,
                               const char *buf) {
  // Safely overwrite the old secret file.
  char *tmp_filename = malloc(strlen(secret_filename) + 2);
  if (tmp_filename == NULL) {
 removal_failure:
    log_message(LOG_ERR, pamh, "Failed to update secret file \"%s\"",
                secret_filename);
    return -1;
  }
  strcat(strcpy(tmp_filename, secret_filename), "~");
  int fd = open(tmp_filename,
                O_WRONLY|O_CREAT|O_NOFOLLOW|O_TRUNC|O_EXCL, 0400);
  if (fd < 0) {
    goto removal_failure;
  }

  // Make sure the secret file is still the same. This prevents attackers
  // from opening a lot of pending sessions and then reusing the same
  // scratch code multiple times.
  struct stat sb;
  if (stat(secret_filename, &sb) != 0 ||
      sb.st_size != old_size ||
      sb.st_mtime != old_mtime) {
    log_message(LOG_ERR, pamh,
                "Secret file \"%s\" changed while trying to use "
                "scratch code\n", secret_filename);
    unlink(tmp_filename);
    free(tmp_filename);
    close(fd);
    return -1;
  }

  // Write the new file contents
  if (write(fd, buf, strlen(buf)) != (ssize_t)strlen(buf) ||
      rename(tmp_filename, secret_filename) != 0) {
    unlink(tmp_filename);
    free(tmp_filename);
    close(fd);
    goto removal_failure;
  }

  free(tmp_filename);
  close(fd);

  return 0;
}

static uint8_t *get_shared_secret(pam_handle_t *pamh,
                                  const char *secret_filename,
                                  const char *buf, int *secretLen) {
  // Decode secret key
  int base32Len = strcspn(buf, "\n");
  *secretLen = (base32Len*5 + 7)/8;
  uint8_t *secret = malloc(base32Len + 1);
  if (secret == NULL) {
    *secretLen = 0;
    return NULL;
  }
  memcpy(secret, buf, base32Len);
  secret[base32Len] = '\000';
  if ((*secretLen = base32_decode(secret, secret, base32Len)) < 1) {
    log_message(LOG_ERR, pamh,
                "Could not find a valid BASE32 encoded secret in \"%s\"",
                secret_filename);
    memset(secret, 0, base32Len);
    free(secret);
    return NULL;
  }
  memset(secret + *secretLen, 0, base32Len + 1 - *secretLen);
  return secret;
}

static int request_verification_code(pam_handle_t *pamh) {
  // Query user for verification code
  const struct pam_message msg = { .msg_style = PAM_PROMPT_ECHO_OFF,
                                   .msg       = "Verification code: " };
  const struct pam_message *msgs = &msg;
  struct pam_response *resp = NULL;
  int retval = converse(pamh, 1, &msgs, &resp);
  int code = -1;
  char *endptr = NULL;
  if (retval != PAM_SUCCESS || resp == NULL || resp[0].resp == NULL ||
      *resp[0].resp == '\000' ||
      ((code = strtoul(resp[0].resp, &endptr, 10)), *endptr)) {
    log_message(LOG_ERR, pamh, "Did not receive verification code from user");
    code = -1;
  }

  // Zero out any copies of the response, and deallocate temporary storage
  if (resp) {
    if (resp[0].resp) {
      memset(resp[0].resp, 0, strlen(resp[0].resp));
      free(resp[0].resp);
    }
    free(resp);
  }

  return code;
}

/* Checks for possible use of scratch codes. Returns -1 on error, 0 on success,
 * and 1, if no scratch code had been entered, and subsequent tests should be
 * applied.
 */
static int check_scratch_codes(pam_handle_t *pamh, const char *secret_filename,
                               off_t old_size, time_t old_mtime,
                               char *buf, int code) {
  // Skip the first line. It contains the shared secret.
  char *ptr = buf + strcspn(buf, "\n");

  // Check if this is one of the scratch codes
  char *endptr = NULL;
  for (;;) {
    // Skip newlines and blank lines
    while (*ptr == '\r' || *ptr == '\n') {
      ptr++;
    }

    // Skip any lines starting with double-quotes. They contain option fields
    if (*ptr == '"') {
      ptr += strcspn(ptr, "\n");
      continue;
    }

    // Try to interpret the line as a scratch code
    int scratchcode = strtoul(ptr, &endptr, 10);

    // Sanity check that we read a valid scratch code. Scratchcodes are all
    // numeric eight-digit codes. There must not be any other information on
    // that line.
    if (ptr == endptr ||
        (*endptr != '\r' && *endptr != '\n' && *endptr) ||
        scratchcode < 10*1000*1000) {
      break;
    }

    // Check if the code matches
    if (scratchcode == code) {
      // Remove scratch code after using it
      memmove(ptr, endptr, strlen(endptr) + 1);
      memset(strrchr(ptr, '\000'), 0, endptr - ptr + 1);
      if (write_file_contents(pamh, secret_filename,
                              old_size, old_mtime, buf) < 0) {
        // Couldn't remove scratch code. Deny access.
        return -1;
      }

      // Successfully removed scratch code. Allow user to log in.
      return 0;
    }
    ptr = endptr;
  }

  // No scratch code has been used. Continue checking other types of codes.
  return 1;
}

#ifdef TESTING
static int timestamp;
void set_timestamp(int ts) {
  timestamp = ts;
}

static int get_timestamp() {
  return timestamp;
}
#else
static int get_timestamp() {
  return time(NULL)/30;
}
#endif

/* If the DISALLOW_REUSE option has been set, record timestamps have been
 * used to log in successfully and disallow their reuse.
 *
 * Returns -1 on error, and 0 on success.
 */
static int invalidate_timebased_code(int tm, pam_handle_t *pamh,
                                     const char *secret_filename,
                                     off_t old_size, time_t old_mtime,
                                     char **buf) {
  char *disallow = strstr(*buf, "\" DISALLOW_REUSE");
  if (!disallow) {
    // Reuse of tokens is not explicitly disallowed. Allow the login request
    // to proceed.
    return 0;
  }
  
  // The DISALLOW_REUSE option is followed by all known timestamps that are
  // currently unavailable for login.
  for (char *ptr = disallow + 2;;) {
    // Find next blocked timestamp value.
    ptr = ptr + strcspn(ptr, " \t\r\n");
    if (*ptr == '\r' || *ptr == '\n') {
      break;
    }

    // Parse timestamp value.
    char *endptr;
    int blocked = strtoul(ptr, &endptr, 10);

    // Stop checking as soon as we reach the end of the line, or when we read
    // a syntactically invalid entry.
    if (ptr == endptr ||
        (*endptr != ' ' && *endptr != '\t' &&
         *endptr != '\r' && *endptr != '\n' && *endptr)) {
      break;
    }

    if (tm == blocked) {
      // The code is currently blocked from use. Disallow login.
      log_message(LOG_ERR, pamh,
                  "Trying to reuse a previously used time-based code. "
                  "Retry again in 30 seconds. "
                  "Warning! This might mean, you are currently subject to a "
                  "man-in-the-middle attack.");
      return -1;
    }

    // If the blocked code is outside of the possible window of timestamps,
    // remove it from the file.
    if (blocked - tm > 3 || tm - blocked > 3) {
      endptr += strspn(endptr, " \t");
      memmove(ptr, endptr, strlen(endptr) + 1);
      memset(strrchr(ptr, '\000'), 0, endptr - ptr + 1);
    } else {
      ptr = endptr;
    }
  }

  // Add the current timestamp to the list of disallowed timestamps.
  char *resized = malloc(strlen(*buf) + 40);
  if (!resized) {
    log_message(LOG_ERR, pamh,
                "Failed to allocate memory when updating \"%s\"",
                secret_filename);
    return -1;
  }
  char *orig = disallow + strcspn(disallow, "\r\n");
  char *ptr = orig + ((char *)memcpy(resized, *buf, orig - *buf) - *buf);
  if (ptr[-1] != ' ') {
    *ptr++ = ' ';
  }
  ptr += sprintf(ptr, "%d", tm);
  memcpy(ptr, orig, strlen(orig) + 1);
  free(*buf);
  *buf = resized;

  // Update the configuration file.
  if (write_file_contents(pamh, secret_filename,
                          old_size, old_mtime, *buf) < 0) {
    // Couldn't add blocked code. Deny access.
    return -1;
  }

  // Allow access.
  return 0;
}

/* Checks for time based verification code. Returns -1 on error, 0 on success,
 * and 1, if no time based code had been entered, and subsequent tests should
 * be applied.
 */
static int check_timebased_code(pam_handle_t *pamh,
                                const char *secret_filename,
                                off_t old_size, time_t old_mtime, char **buf,
                                const uint8_t *secret, int secretLen,
                                int code) {
  if (!is_totp(*buf)) {
    // The secret file does not actual contain information for a time-based
    // code. Return to caller and see if any other authentication methods
    // apply.
    return 1;
  }

  if (code < 0 || code >= 1000000) {
    // All time based verification codes are no longer than six digits.
    return 1;
  }

  // Compute verification codes and compare them with user input
  int tm = get_timestamp();
  for (int i = -1; i <= 1; ++i) {
    uint8_t challenge[8];
    unsigned long chlg = tm + i;
    for (int j = 8; j--; chlg >>= 8) {
      challenge[j] = chlg;
    }
    uint8_t hash[SHA1_DIGEST_LENGTH];
    hmac_sha1(secret, secretLen, challenge, 8, hash, SHA1_DIGEST_LENGTH);
    int offset = hash[SHA1_DIGEST_LENGTH - 1] & 0xF;
    unsigned int truncatedHash = 0;
    for (int j = 0; j < 4; ++j) {
      truncatedHash <<= 8;
      truncatedHash  |= hash[offset + j];
    }
    memset(hash, 0, sizeof(hash));
    truncatedHash &= 0x7FFFFFFF;
    truncatedHash %= 1000000;
    if (truncatedHash == (unsigned int)code) {
      return invalidate_timebased_code(tm + i, pamh, secret_filename,
                                       old_size, old_mtime, buf);
    }
  }
  return -1;
}

static int google_authenticator(pam_handle_t *pamh, int flags,
                                int argc, const char **argv) {
  int        rc = PAM_SESSION_ERR;
  const char *username;
  char       *secret_filename = NULL;
  int        uid, old_uid = -1, fd = -1;
  off_t      filesize;
  time_t     mtime;
  char       *buf = NULL;
  uint8_t    *secret = NULL;
  int        secretLen = 0;
  int        code = -1;

  // Read and process status file, then ask the user for the verification code.
  if ((username = get_user_name(pamh)) &&
      (secret_filename = get_secret_filename(pamh, username, &uid)) &&
      (old_uid = drop_privileges(pamh, username, uid)) >= 0 &&
      (fd = open_secret_file(pamh, secret_filename, username, uid,
                             &filesize, &mtime)) >= 0 &&
      (buf = read_file_contents(pamh, secret_filename, fd, filesize)) &&
      (secret = get_shared_secret(pamh, secret_filename, buf, &secretLen)) &&
      (code = request_verification_code(pamh)) >= 0) {
    // Check all possible types of verification codes.
    switch (check_scratch_codes(pamh, secret_filename, filesize, mtime,
                                buf, code)) {
      case 1:
        switch (check_timebased_code(pamh, secret_filename, filesize, mtime,
                                     &buf, secret, secretLen, code)) {
          case 0:
            rc = PAM_SUCCESS;
            break;
          default:
            break;
        }
        break;
      case 0:
        rc = PAM_SUCCESS;
        break;
      default:
        break;
    }

    // If nothing matched, so an error message
    if (rc != PAM_SUCCESS) {
      log_message(LOG_ERR, pamh, "Invalid verification code");
    }
  }

  // Clean up
  if (secret) {
    memset(secret, 0, secretLen);
    free(secret);
  }
  if (buf) {
    memset(buf, 0, strlen(buf));
    free(buf);
  }
  if (fd >= 0) {
    close(fd);
  }
  if (old_uid >= 0) {
    setfsuid(old_uid);
  }
  free(secret_filename);
  return rc;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                   int argc, const char **argv) {
  return google_authenticator(pamh, flags, argc, argv);
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
                                     const char **argv) {
  return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags,
                                   int argc, const char **argv) {
  return google_authenticator(pamh, flags, argc, argv);
}

#ifdef PAM_STATIC
struct pam_module _pam_listfile_modstruct = {
  MODULE_NAME,
  pam_sm_authenticate,
  pam_sm_setcred,
  NULL,
  pam_sm_open_session,
  NULL,
  NULL
};
#endif
