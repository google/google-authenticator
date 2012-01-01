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
#include <getopt.h>
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

static enum { QR_UNSET=0, QR_NONE, QR_ANSI, QR_UTF8 } qr_mode = QR_UNSET;

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
    if (!user) {
      perror("malloc()");
      _exit(1);
    }
  }
  free(buf);
  return user;
}

static const char *urlEncode(const char *s) {
  char *ret = malloc(3*strlen(s) + 1);
  char *d = ret;
  do {
    switch (*s) {
    case '%':
    case '&':
    case '?':
    case '=':
    encode:
      sprintf(d, "%%%02X", (unsigned char)*s);
      d += 3;
      break;
    default:
      if ((*s && *s <= ' ') || *s >= '\x7F') {
        goto encode;
      }
      *d++ = *s;
      break;
    }
  } while (*s++);
  ret = realloc(ret, strlen(ret) + 1);
  return ret;
}

static const char *getURL(const char *secret, const char *label,
                          char **encoderURL, const int use_totp) {
  const char *encodedLabel = urlEncode(label);
  char *url = malloc(strlen(encodedLabel) + strlen(secret) + 80);
  char totp = 'h';
  if (use_totp) {
    totp = 't';
  }
  sprintf(url, "otpauth://%cotp/%s?secret=%s", totp, encodedLabel, secret);
  if (encoderURL) {
    const char *encoder = "https://www.google.com/chart?chs=200x200&"
                          "chld=M|0&cht=qr&chl=";
    const char *encodedURL = urlEncode(url);
    
    *encoderURL = strcat(strcpy(malloc(strlen(encoder) +
                                       strlen(encodedURL) + 1),
                                encoder), encodedURL);
    free((void *)encodedURL);
  }
  free((void *)encodedLabel);
  return url;
}

#define ANSI_RESET        "\x1B[0m"
#define ANSI_BLACKONGREY  "\x1B[30;47;27m"
#define ANSI_WHITE        "\x1B[27m"
#define ANSI_BLACK        "\x1B[7m"
#define UTF8_BOTH         "\xE2\x96\x88"
#define UTF8_TOPHALF      "\xE2\x96\x80"
#define UTF8_BOTTOMHALF   "\xE2\x96\x84"

static void displayQRCode(const char *secret, const char *label,
                          const int use_totp) {
  if (qr_mode == QR_NONE) {
    return;
  }
  char *encoderURL;
  const char *url = getURL(secret, label, &encoderURL, use_totp);
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
        if (qr_mode != QR_UTF8) {
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

static void usage(void) {
  puts(
 "google-authenticator [<options>]\n"
 " -h, --help               Print this message\n"
 " -c, --counter-based      Set up counter-based (HOTP) verification\n"
 " -t, --time-based         Set up time-based (TOTP) verification\n"
 " -d, --disallow-reuse     Disallow reuse of previously used TOTP tokens\n"
 " -D, --allow-reuse        Allow reuse of previously used TOTP tokens\n"
 " -f, --force              Write file without first confirming with user\n"
 " -l, --label=<label>      Override the default label in \"otpauth://\" URL\n"
 " -q, --quiet              Quiet mode\n"
 " -Q, --qr-mode={NONE,ANSI,UTF8}\n"
 " -r, --rate-limit=N       Limit logins to N per every M seconds\n"
 " -R, --rate-time=M        Limit logins to N per every M seconds\n"
 " -u, --no-rate-limit      Disable rate-limiting\n"
 " -s, --secret=<file>      Specify a non-standard file location\n"
 " -w, --window-size=W      Set window of concurrently valid codes\n"
 " -W, --minimal-window     Disable window of concurrently valid codes");
}

int main(int argc, char *argv[]) {
  uint8_t buf[SECRET_BITS/8 + SCRATCHCODES*BYTES_PER_SCRATCHCODE];
  static const char hotp[]      = "\" HOTP_COUNTER 1\n";
  static const char totp[]      = "\" TOTP_AUTH\n";
  static const char disallow[]  = "\" DISALLOW_REUSE\n";
  static const char window[]    = "\" WINDOW_SIZE 17\n";
  static const char ratelimit[] = "\" RATE_LIMIT 3 30\n";
  char secret[(SECRET_BITS + BITS_PER_BASE32_CHAR-1)/BITS_PER_BASE32_CHAR +
              1 /* newline */ +
              sizeof(hotp) +  // hotp and totp are mutually exclusive.
              sizeof(disallow) +
              sizeof(window) +
              sizeof(ratelimit) + 5 + // NN MMM (total of five digits)
              SCRATCHCODE_LENGTH*(SCRATCHCODES + 1 /* newline */) +
              1 /* NUL termination character */];

  enum { ASK_MODE, HOTP_MODE, TOTP_MODE } mode = ASK_MODE;
  enum { ASK_REUSE, DISALLOW_REUSE, ALLOW_REUSE } reuse = ASK_REUSE;
  int force = 0, quiet = 0;
  int r_limit = 0, r_time = 0;
  char *secret_fn = NULL;
  char *label = NULL;
  int window_size = 0;
  int idx;
  for (;;) {
    static const char optstring[] = "+hctdDfl:qQ:r:R:us:w:W";
    static struct option options[] = {
      { "help",             0, 0, 'h' },
      { "counter-based",    0, 0, 'c' },
      { "time-based",       0, 0, 't' },
      { "disallow-reuse",   0, 0, 'd' },
      { "allow-reuse",      0, 0, 'D' },
      { "force",            0, 0, 'f' },
      { "label",            1, 0, 'l' },
      { "quiet",            0, 0, 'q' },
      { "qr-mode",          1, 0, 'Q' },
      { "rate-limit",       1, 0, 'r' },
      { "rate-time",        1, 0, 'R' },
      { "no-rate-limit",    0, 0, 'u' },
      { "secret",           1, 0, 's' },
      { "window-size",      1, 0, 'w' },
      { "minimal-window",   0, 0, 'W' },
      { 0,                  0, 0,  0  }
    };
    idx = -1;
    int c = getopt_long(argc, argv, optstring, options, &idx);
    if (c > 0) {
      for (int i = 0; options[i].name; i++) {
        if (options[i].val == c) {
          idx = i;
          break;
        }
      }
    } else if (c < 0) {
      break;
    }
    if (idx-- <= 0) {
      // Help (or invalid argument)
    err:
      usage();
      if (idx < -1) {
        fprintf(stderr, "Failed to parse command line\n");
        _exit(1);
      }
      exit(0);
    } else if (!idx--) {
      // counter-based
      if (mode != ASK_MODE) {
        fprintf(stderr, "Duplicate -c and/or -t option detected\n");
        _exit(1);
      }
      if (reuse != ASK_REUSE) {
      reuse_err:
        fprintf(stderr, "Reuse of tokens is not a meaningful parameter "
                "when in counter-based mode\n");
        _exit(1);
      }
      mode = HOTP_MODE;
    } else if (!idx--) {
      // time-based
      if (mode != ASK_MODE) {
        fprintf(stderr, "Duplicate -c and/or -t option detected\n");
        _exit(1);
      }
      mode = TOTP_MODE;
    } else if (!idx--) {
      // disallow-reuse
      if (reuse != ASK_REUSE) {
        fprintf(stderr, "Duplicate -d and/or -D option detected\n");
        _exit(1);
      }
      if (mode == HOTP_MODE) {
        goto reuse_err;
      }
      reuse = DISALLOW_REUSE;
    } else if (!idx--) {
      // allow-reuse
      if (reuse != ASK_REUSE) {
        fprintf(stderr, "Duplicate -d and/or -D option detected\n");
        _exit(1);
      }
      if (mode == HOTP_MODE) {
        goto reuse_err;
      }
      reuse = ALLOW_REUSE;
    } else if (!idx--) {
      // force
      if (force) {
        fprintf(stderr, "Duplicate -f option detected\n");
        _exit(1);
      }
      force = 1;
    } else if (!idx--) {
      // label
      if (label) {
        fprintf(stderr, "Duplicate -l option detected\n");
        _exit(1);
      }
      label = strdup(optarg);
    } else if (!idx--) {
      // quiet
      if (quiet) {
        fprintf(stderr, "Duplicate -q option detected\n");
        _exit(1);
      }
      quiet = 1;
    } else if (!idx--) {
      // qr-mode
      if (qr_mode != QR_UNSET) {
        fprintf(stderr, "Duplicate -Q option detected\n");
        _exit(1);
      }
      if (!strcasecmp(optarg, "none")) {
        qr_mode = QR_NONE;
      } else if (!strcasecmp(optarg, "ansi")) {
        qr_mode = QR_ANSI;
      } else if (!strcasecmp(optarg, "utf8")) {
        qr_mode = QR_UTF8;
      } else {
        fprintf(stderr, "Invalid qr-mode \"%s\"\n", optarg);
        _exit(1);
      }
    } else if (!idx--) {
      // rate-limit
      if (r_limit > 0) {
        fprintf(stderr, "Duplicate -r option detected\n");
        _exit(1);
      } else if (r_limit < 0) {
        fprintf(stderr, "-u is mutually exclusive with -r\n");
        _exit(1);
      }
      char *endptr;
      errno = 0;
      long l = strtol(optarg, &endptr, 10);
      if (errno || endptr == optarg || *endptr || l < 1 || l > 10) {
        fprintf(stderr, "-r requires an argument in the range 1..10\n");
        _exit(1);
      }
      r_limit = (int)l;
    } else if (!idx--) {
      // rate-time
      if (r_time > 0) {
        fprintf(stderr, "Duplicate -R option detected\n");
        _exit(1);
      } else if (r_time < 0) {
        fprintf(stderr, "-u is mutually exclusive with -R\n");
        _exit(1);
      }
      char *endptr;
      errno = 0;
      long l = strtol(optarg, &endptr, 10);
      if (errno || endptr == optarg || *endptr || l < 15 || l > 600) {
        fprintf(stderr, "-R requires an argument in the range 15..600\n");
        _exit(1);
      }
      r_time = (int)l;
    } else if (!idx--) {
      // no-rate-limit
      if (r_limit > 0 || r_time > 0) {
        fprintf(stderr, "-u is mutually exclusive with -r/-R\n");
        _exit(1);
      }
      if (r_limit < 0) {
        fprintf(stderr, "Duplicate -u option detected\n");
        _exit(1);
      }
      r_limit = r_time = -1;
    } else if (!idx--) {
      // secret
      if (secret_fn) {
        fprintf(stderr, "Duplicate -s option detected\n");
        _exit(1);
      }
      if (!*optarg) {
        fprintf(stderr, "-s must be followed by a filename\n");
        _exit(1);
      }
      secret_fn = strdup(optarg);
      if (!secret_fn) {
        perror("malloc()");
        _exit(1);
      }
    } else if (!idx--) {
      // window-size
      if (window_size) {
        fprintf(stderr, "Duplicate -w/-W option detected\n");
        _exit(1);
      }
      char *endptr;
      errno = 0;
      long l = strtol(optarg, &endptr, 10);
      if (errno || endptr == optarg || *endptr || l < 1 || l > 21) {
        fprintf(stderr, "-w requires an argument in the range 1..21\n");
        _exit(1);
      }
      window_size = (int)l;
    } else if (!idx--) {
      // minimal-window
      if (window_size) {
        fprintf(stderr, "Duplicate -w/-W option detected\n");
        _exit(1);
      }
      window_size = -1;
    } else {
      fprintf(stderr, "Error\n");
      _exit(1);
    }
  }
  idx = -1;
  if (optind != argc) {
    goto err;
  }
  if (reuse != ASK_REUSE && mode != TOTP_MODE) {
    fprintf(stderr, "Must select time-based mode, when using -d or -D\n");
    _exit(1);
  }
  if ((r_time && !r_limit) || (!r_time && r_limit)) {
    fprintf(stderr, "Must set -r when setting -R, and vice versa\n");
    _exit(1);
  }
  if (!label) {
    uid_t uid = getuid();
    const char *user = getUserName(uid);
    char hostname[128] = { 0 };
    if (gethostname(hostname, sizeof(hostname)-1)) {
      strcpy(hostname, "unix");
    }
    label = strcat(strcat(strcpy(malloc(strlen(user) + strlen(hostname) + 2),
                                 user), "@"), hostname);
    free((char *)user);
  }
  int fd = open("/dev/urandom", O_RDONLY);
  if (fd < 0) {
    perror("Failed to open \"/dev/urandom\"");
    return 1;
  }
  if (read(fd, buf, sizeof(buf)) != sizeof(buf)) {
  urandom_failure:
    perror("Failed to read from \"/dev/urandom\"");
    return 1;
  }

  base32_encode(buf, SECRET_BITS/8, (uint8_t *)secret, sizeof(secret));
  int use_totp;
  if (mode == ASK_MODE) {
    use_totp = maybe("Do you want authentication tokens to be time-based");
  } else {
    use_totp = mode == TOTP_MODE;
  }
  if (!quiet) {
    displayQRCode(secret, label, use_totp);
    printf("Your new secret key is: %s\n", secret);
    printf("Your verification code is %06d\n", generateCode(secret, 0));
    printf("Your emergency scratch codes are:\n");
  }
  free(label);
  strcat(secret, "\n");
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
    if (!quiet) {
      printf("  %08d\n", scratch);
    }
    snprintf(strrchr(secret, '\000'), sizeof(secret) - strlen(secret),
             "%08d\n", scratch);
  }
  close(fd);
  if (!secret_fn) {
    char *home = getenv("HOME");
    if (!home || *home != '/') {
      fprintf(stderr, "Cannot determine home directory\n");
      return 1;
    }
    secret_fn = malloc(strlen(home) + strlen(SECRET) + 1);
    if (!secret_fn) {
      perror("malloc()");
      _exit(1);
    }
    strcat(strcpy(secret_fn, home), SECRET);
  }
  if (!force) {
    printf("\nDo you want me to update your \"%s\" file (y/n) ", secret_fn);
    fflush(stdout);
    char ch;
    do {
      ch = getchar();
    } while (ch == ' ' || ch == '\r' || ch == '\n');
    if (ch != 'y' && ch != 'Y') {
      exit(0);
    }
  }
  secret_fn = realloc(secret_fn, 2*strlen(secret_fn) + 3);
  if (!secret_fn) {
    perror("malloc()");
    _exit(1);
  }
  char *tmp_fn = strrchr(secret_fn, '\000') + 1;
  strcat(strcpy(tmp_fn, secret_fn), "~");

  // Add optional flags.
  if (use_totp) {
    if (reuse == ASK_REUSE) {
      maybeAddOption("Do you want to disallow multiple uses of the same "
                     "authentication\ntoken? This restricts you to one login "
                     "about every 30s, but it increases\nyour chances to "
                     "notice or even prevent man-in-the-middle attacks",
                     secret, sizeof(secret), disallow);
    } else if (reuse == DISALLOW_REUSE) {
      addOption(secret, sizeof(secret), disallow);
    }
    if (!window_size) {
      maybeAddOption("By default, tokens are good for 30 seconds and in order "
                     "to compensate for\npossible time-skew between the "
                     "client and the server, we allow an extra\ntoken before "
                     "and after the current time. If you experience problems "
                     "with poor\ntime synchronization, you can increase the "
                     "window from its default\nsize of 1:30min to about 4min. "
                     "Do you want to do so",
                     secret, sizeof(secret), window);
    } else {
      char buf[80];
      sprintf(buf, "\" WINDOW_SIZE %d\n", window_size);
      addOption(secret, sizeof(secret), buf);
    }
  } else {
    if (!window_size) {
      maybeAddOption("By default, three tokens are valid at any one time.  "
                     "This accounts for\ngenerated-but-not-used tokens and "
                     "failed login attempts. In order to\ndecrease the "
                     "likelihood of synchronization problems, this window "
                     "can be\nincreased from its default size of 3 to 17. Do "
                     "you want to do so",
                     secret, sizeof(secret), window);
    } else {
      char buf[80];
      sprintf(buf, "\" WINDOW_SIZE %d\n",
              window_size > 0 ? window_size : use_totp ? 3 : 1);
      addOption(secret, sizeof(secret), buf);
    }
  }
  if (!r_limit && !r_time) {
    maybeAddOption("If the computer that you are logging into isn't hardened "
                   "against brute-force\nlogin attempts, you can enable "
                   "rate-limiting for the authentication module.\nBy default, "
                   "this limits attackers to no more than 3 login attempts "
                   "every 30s.\nDo you want to enable rate-limiting",
                   secret, sizeof(secret), ratelimit);
  } else if (r_limit > 0 && r_time > 0) {
    char buf[80];
    sprintf(buf, "\"RATE_LIMIT %d %d\n", r_limit, r_time);
    addOption(secret, sizeof(secret), buf);
  }

  fd = open(tmp_fn, O_WRONLY|O_EXCL|O_CREAT|O_NOFOLLOW|O_TRUNC, 0400);
  if (fd < 0) {
    fprintf(stderr, "Failed to create \"%s\" (%s)",
            secret_fn, strerror(errno));
    free(secret_fn);
    return 1;
  }
  if (write(fd, secret, strlen(secret)) != (ssize_t)strlen(secret) ||
      rename(tmp_fn, secret_fn)) {
    perror("Failed to write new secret");
    unlink(secret_fn);
    close(fd);
    free(secret_fn);
    return 1;
  }

  free(secret_fn);
  close(fd);

  return 0;
}
