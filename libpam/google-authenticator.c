// Helper program to generate a new secret for use in two-factor
// authentication.
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

#include <assert.h>
#include <errno.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "base32.h"
#include "hmac.h"
#include "sha1.h"

#define SECRET                    "/.google_authenticator"
#define SECRET_BITS               80          // Must be divisible by eight
#define VERIFICATION_CODE_MODULUS (1000*1000) // Six digits
#define SCRATCHCODES              5           // Number of initial scratchcodes
#define SCRATCHCODE_LENGTH        8           // Eight digits per scratchcode
#define BYTES_PER_SCRATCHCODE     4           // 32bit of randomness is enough
#define BITS_PER_BASE32_CHAR      5           // Base32 expands space by 8/5

static int useBlockElements = 0;

static int generateCode(const char *key, unsigned long tm) {
  uint8_t challenge[8];
  for (int i = 8; i--; tm >>= 8) {
    challenge[i] = tm;
  }

  // Estimated number of bytes needed to represent the decoded secret. Because
  // of white-space and separators, this is an upper bound of the real number,
  // which we later get as a return-value from base32_decode()
  int secretLen = (strlen(key) + 7)/8*BITS_PER_BASE32_CHAR;

  // Sanity check, that our secret will fixed into a reasonably-sized static
  // array.
  if (secretLen <= 0 || secretLen > 100) {
    return -1;
  }

  // Decode secret from Base32 to a binary representation, and check that we
  // have at least one byte's worth of secret data.
  uint8_t secret[100];
  if ((secretLen = base32_decode((const uint8_t *)key, secret, secretLen))<1) {
    return -1;
  }

  // Compute the HMAC_SHA1 of the secrete and the challenge.
  uint8_t hash[SHA1_DIGEST_LENGTH];
  hmac_sha1(secret, secretLen, challenge, 8, hash, SHA1_DIGEST_LENGTH);

  // Pick the offset where to sample our hash value for the actual verification
  // code.
  int offset = hash[SHA1_DIGEST_LENGTH - 1] & 0xF;

  // Compute the truncated hash in a byte-order independent loop.
  unsigned int truncatedHash = 0;
  for (int i = 0; i < 4; ++i) {
    truncatedHash <<= 8;
    truncatedHash  |= hash[offset + i];
  }

  // Truncate to a smaller number of digits.
  truncatedHash &= 0x7FFFFFFF;
  truncatedHash %= VERIFICATION_CODE_MODULUS;

  return truncatedHash;
}

static const char *getUserName(uid_t uid) {
  struct passwd pwbuf, *pw;
  char *buf;
  #ifdef _SC_GETPW_R_SIZE_MAX
  int len = sysconf(_SC_GETPW_R_SIZE_MAX);
  if (len <= 0) {
    len = 4096;
  }
  #else
  int len = 4096;
  #endif
  buf = malloc(len);
  char *user;
  if (getpwuid_r(uid, &pwbuf, buf, len, &pw) || !pw) {
    user = malloc(32);
    snprintf(user, 32, "%d", uid);
  } else {
    user = strdup(pw->pw_name);
  }
  free(buf);
  return user;
}

static const char *getURL(const char *secret, char **encoderURL,
                          const int use_totp) {
  uid_t uid = getuid();
  const char *user = getUserName(uid);
  char hostname[128] = { 0 };
  if (gethostname(hostname, sizeof(hostname)-1)) {
    strcpy(hostname, "unix");
  }
  char *url = malloc(strlen(user) + strlen(hostname) + strlen(secret) + 80);
  char totp = 'h';
  if (use_totp) {
    totp = 't';
  }
  sprintf(url, "otpauth://%cotp/%s@%s?secret=%s", totp, user, hostname, secret);
  if (encoderURL) {
    const char *encoder = "https://www.google.com/chart?chs=200x200&"
                          "chld=M|0&cht=qr&chl=";
    *encoderURL = malloc(strlen(encoder) + strlen(url) + 6);
    sprintf(*encoderURL, "%sotpauth://%cotp/%s@%s%%3Fsecret%%3D%s",
            encoder, totp, user, hostname, secret);
  }
  free((char *)user);
  return url;
}

#define ANSI_RESET        "\x1B[0m"
#define ANSI_BLACKONGREY  "\x1B[30;47;27m"
#define ANSI_WHITE        "\x1B[27m"
#define ANSI_BLACK        "\x1B[7m"
#define UTF8_BOTH         "\xE2\x96\x88"
#define UTF8_TOPHALF      "\xE2\x96\x80"
#define UTF8_BOTTOMHALF   "\xE2\x96\x84"

static void displayQRCode(const char *secret, const int use_totp) {
  char *encoderURL;
  const char *url = getURL(secret, &encoderURL, use_totp);
  puts(encoderURL);

  // Only newer systems have support for libqrencode. So, instead of requiring
  // it at build-time, we look for it at run-time. If it cannot be found, the
  // user can still type the code in manually, or he can copy the URL into
  // his browser.
  if (isatty(1)) {
    void *qrencode = dlopen("libqrencode.so.2", RTLD_NOW | RTLD_LOCAL);
    if (!qrencode) {
      qrencode = dlopen("libqrencode.so.3", RTLD_NOW | RTLD_LOCAL);
    }
    if (qrencode) {
      typedef struct {
        int version;
        int width;
        unsigned char *data;
      } QRcode;
      QRcode *(*QRcode_encodeString8bit)(const char *, int, int) =
        (QRcode *(*)(const char *, int, int))
        dlsym(qrencode, "QRcode_encodeString8bit");
      void (*QRcode_free)(QRcode *qrcode) =
        (void (*)(QRcode *))dlsym(qrencode, "QRcode_free");
      if (QRcode_encodeString8bit && QRcode_free) {
        QRcode *qrcode = QRcode_encodeString8bit(url, 0, 1);
        char *ptr = (char *)qrcode->data;
        // Output QRCode using ANSI colors. Instead of black on white, we
        // output black on grey, as that works independently of whether the
        // user runs his terminals in a black on white or white on black color
        // scheme.
        // But this requires that we print a border around the entire QR Code.
        // Otherwise, readers won't be able to recognize it.
        if (!useBlockElements) {
          for (int i = 0; i < 2; ++i) {
            printf(ANSI_BLACKONGREY);
            for (int x = 0; x < qrcode->width + 4; ++x) printf("  ");
            puts(ANSI_RESET);
          }
          for (int y = 0; y < qrcode->width; ++y) {
            printf(ANSI_BLACKONGREY"    ");
            int isBlack = 0;
            for (int x = 0; x < qrcode->width; ++x) {
              if (*ptr++ & 1) {
                if (!isBlack) {
                  printf(ANSI_BLACK);
                }
                isBlack = 1;
              } else {
                if (isBlack) {
                  printf(ANSI_WHITE);
                }
                isBlack = 0;
              }
              printf("  ");
            }
            if (isBlack) {
              printf(ANSI_WHITE);
            }
            puts("    "ANSI_RESET);
          }
          for (int i = 0; i < 2; ++i) {
            printf(ANSI_BLACKONGREY);
            for (int x = 0; x < qrcode->width + 4; ++x) printf("  ");
            puts(ANSI_RESET);
          }
        } else {
          // Drawing the QRCode with Unicode block elements is desirable as
          // it makes the code much smaller, which is often easier to scan.
          // Unfortunately, many terminal emulators do not display these
          // Unicode characters properly.
          printf(ANSI_BLACKONGREY);
          for (int i = 0; i < qrcode->width + 4; ++i) {
            printf(" ");
          }
          puts(ANSI_RESET);
          for (int y = 0; y < qrcode->width; y += 2) {
            printf(ANSI_BLACKONGREY"  ");
            for (int x = 0; x < qrcode->width; ++x) {
              int top = qrcode->data[y*qrcode->width + x] & 1;
              int bottom = 0;
              if (y+1 < qrcode->width) {
                bottom = qrcode->data[(y+1)*qrcode->width + x] & 1;
              }
              if (top) {
                if (bottom) {
                  printf(UTF8_BOTH);
                } else {
                  printf(UTF8_TOPHALF);
                }
              } else {
                if (bottom) {
                  printf(UTF8_BOTTOMHALF);
                } else {
                  printf(" ");
                }
              }
            }
            puts("  "ANSI_RESET);
          }
          printf(ANSI_BLACKONGREY);
          for (int i = 0; i < qrcode->width + 4; ++i) {
            printf(" ");
          }
          puts(ANSI_RESET);
        }
        QRcode_free(qrcode);
      }
      dlclose(qrencode);
    }
  }

  free((char *)url);
  free(encoderURL);
}

static int maybe(const char *msg) {
  printf("\n%s (y/n) ", msg);
  fflush(stdout);
  char ch;
  do {
    ch = getchar();
  } while (ch == ' ' || ch == '\r' || ch == '\n');
  if (ch == 'y' || ch == 'Y') {
    return 1;
  }
  return 0;
}

static char *addOption(char *buf, size_t nbuf, const char *option) {
  assert(strlen(buf) + strlen(option) < nbuf);
  char *scratchCodes = strchr(buf, '\n');
  assert(scratchCodes);
  scratchCodes++;
  memmove(scratchCodes + strlen(option), scratchCodes,
          strlen(scratchCodes) + 1);
  memcpy(scratchCodes, option, strlen(option));
  return buf;
}

static char *maybeAddOption(const char *msg, char *buf, size_t nbuf,
                            const char *option) {
  if (maybe(msg)) {
    buf = addOption(buf, nbuf, option);
  }
  return buf;
}

int main(int argc, char *argv[]) {
  int fd = open("/dev/urandom", O_RDONLY);
  if (fd < 0) {
    perror("Failed to open \"/dev/urandom\"");
    return 1;
  }
  uint8_t buf[SECRET_BITS/8 + SCRATCHCODES*BYTES_PER_SCRATCHCODE];
  static const char hotp[]      = "\" HOTP_COUNTER 1\n";
  static const char totp[]      = "\" TOTP_AUTH\n";
  static const char disallow[]  = "\" DISALLOW_REUSE\n";
  static const char window[]    = "\" WINDOW_SIZE 17\n";
  static const char ratelimit[] = "\" RATE_LIMIT 3 30\n";
  char    secret[(SECRET_BITS + BITS_PER_BASE32_CHAR-1)/BITS_PER_BASE32_CHAR +
                 1 /* newline */ +
                 sizeof(hotp) +  // hotp and totp are mutually exclusive.
                 sizeof(disallow) +
                 sizeof(window) +
                 sizeof(ratelimit) +
                 SCRATCHCODE_LENGTH*(SCRATCHCODES + 1 /* newline */) +
                 1 /* NUL termination character */];
  if (read(fd, buf, sizeof(buf)) != sizeof(buf)) {
  urandom_failure:
    perror("Failed to read from \"/dev/urandom\"");
    return 1;
  }

  base32_encode(buf, SECRET_BITS/8, (uint8_t *)secret, sizeof(secret));
  int use_totp = maybe("Do you want authentication tokens to be time-based");
  displayQRCode(secret, use_totp);
  strcat(secret, "\n");
  printf("Your new secret key is: %s", secret);
  printf("Your verification code is %06d\n", generateCode(secret, 0));
  printf("Your emergency scratch codes are:\n");
  if (use_totp) {
    strcat(secret, totp);
  } else {
    strcat(secret, hotp);
  }
  for (int i = 0; i < SCRATCHCODES; ++i) {
  new_scratch_code:;
    int scratch = 0;
    for (int j = 0; j < BYTES_PER_SCRATCHCODE; ++j) {
      scratch = 256*scratch + buf[SECRET_BITS/8 + BYTES_PER_SCRATCHCODE*i + j];
    }
    int modulus = 1;
    for (int j = 0; j < SCRATCHCODE_LENGTH; j++) {
      modulus *= 10;
    }
    scratch = (scratch & 0x7FFFFFFF) % modulus;
    if (scratch < modulus/10) {
      // Make sure that scratch codes are always exactly eight digits. If they
      // start with a sequence of zeros, just generate a new scratch code.
      if (read(fd, buf + (SECRET_BITS/8 + BYTES_PER_SCRATCHCODE*i),
               BYTES_PER_SCRATCHCODE) != BYTES_PER_SCRATCHCODE) {
        goto urandom_failure;
      }
      goto new_scratch_code;
    }
    printf("  %08d\n", scratch);
    snprintf(strrchr(secret, '\000'), sizeof(secret) - strlen(secret),
             "%08d\n", scratch);
  }
  close(fd);
  printf("\nDo you want me to update your \"~%s\" file (y/n) ", SECRET);
  fflush(stdout);
  char ch;
  do {
    ch = getchar();
  } while (ch == ' ' || ch == '\r' || ch == '\n');
  if (ch == 'y' || ch == 'Y') {
    char *home = getenv("HOME");
    if (!home || *home != '/') {
      fprintf(stderr, "Cannot determine home directory\n");
      return 1;
    }

    char *fn = calloc(1, 2*(strlen(home) + strlen(SECRET) + 2));
    if (!fn) {
      perror("Cannot allocate space for filename");
      return 1;
    }
    strcat(strcpy(fn, home), SECRET "~");
    char *tmp_fn = strrchr(fn, '\000');
    memcpy(tmp_fn, fn, strlen(fn));
    tmp_fn[-1] = '\000';

    // Add optional flags.
    if (use_totp) {
      maybeAddOption("Do you want to disallow multiple uses of the same "
                     "authentication\ntoken? This restricts you to one login "
                     "about every 30s, but it increases\nyour chances to "
                     "notice or even prevent man-in-the-middle attacks",
                     secret, sizeof(secret), disallow);
      maybeAddOption("By default, tokens are good for 30 seconds and in order "
                     "to compensate for\npossible time-skew between the client "
                     "and the server, we allow an extra\ntoken before and "
                     "after the current time. If you experience problems with "
                     "poor\ntime synchronization, you can increase the window "
                     "from its default\nsize of 1:30min to about 4min. Do you "
                     "want to do so",
                     secret, sizeof(secret), window);
    } else {
      maybeAddOption("By default, three tokens are valid at any one time.  "
                     "This accounts for\ngenerated-but-not-used tokens and "
                     "failed login attempts. In order to\ndecrease the "
                     "likelihood of synchronization problems, this window "
                     "can be\nincreased from its default size of 3 to 17. Do "
                     "you want to do so",
                     secret, sizeof(secret), window);
    }
    maybeAddOption("If the computer that you are logging into isn't hardened "
                   "against brute-force\nlogin attempts, you can enable "
                   "rate-limiting for the authentication module.\nBy default, "
                   "this limits attackers to no more than 3 login attempts "
                   "every 30s.\nDo you want to enable rate-limiting",
                   secret, sizeof(secret), ratelimit);

    fd = open(tmp_fn, O_WRONLY|O_EXCL|O_CREAT|O_NOFOLLOW|O_TRUNC, 0400);
    if (fd < 0) {
      perror("Failed to create \"~"SECRET"\"");
      free(fn);
      return 1;
    }
    if (write(fd, secret, strlen(secret)) != (ssize_t)strlen(secret) ||
        rename(tmp_fn, fn)) {
      perror("Failed to write new secret");
      unlink(fn);
      close(fd);
      free(fn);
      return 1;
    }

    free(fn);
    close(fd);
  }

  return 0;
}
