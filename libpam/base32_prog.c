// Base32 utility program
//
// Copyright 2015 TWO SIGMA OPEN SOURCE, LLC
// Author: Eric Haszlakiewicz
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

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "base32.h"

/*
 * Convert arbitrary input from a file to base-32 encoded output on stdout.
 * Decode base-32 input from a file or from the command line to arbitrary
 * output on stdout.
 *
 * ~/google-authenticator/libpam/base32 e $(awk '{ print $2 }' < gauth.seed | xxd -r -p)
 */

enum modes {
	ENCODE_NONE = 0,
	ENCODE_FILE = 1,
	DECODE_FILE = 2,
	DECODE_STRING = 3,
};

static void usage(const char *argv0, int exitval, char *errmsg) __attribute__((noreturn));
static void usage(const char *argv0, int exitval, char *errmsg)
{
	FILE *f = stdout;
	if (errmsg) {
		fprintf(stderr, "ERROR: %s\n", errmsg);
		f = stderr;
	}
	
	fprintf(f, "Usage: %s -e [<file>]\n", argv0);
	fprintf(f, "Usage: %s -d [<file>]\n", argv0);
	fprintf(f, "Usage: %s -D <value>\n", argv0);
	fprintf(f, "  Emits <value> encoded in/decoded from base-32 on stdout.\n");
	fprintf(f, "  When encoding, the file should contain raw binary data.\n");
	fprintf(f, "   If no filename is specified, it reads from stdin.\n");
	fprintf(f, "  All output is written to stdout.\n");

	exit(exitval);
}

/* Write the full contents of buf to the given file descriptor,
 * even across multiple short writes.
 * If write() fails, exit with an error.
 */
static void full_write(int fd, uint8_t *buf, size_t remaining);
static void full_write(int fd, uint8_t *buf, size_t remaining)
{
	ssize_t offset, written;
	for (offset = 0; remaining != 0; remaining -= written, offset += written)
		if ((written = write(fd, buf + offset, remaining)) < 0)
			err(1, "Failed to write to stdout");
}

int main(int argc, char *argv[]) {
	int c;
	int mode = ENCODE_NONE;
	while ((c = getopt(argc, argv, "edDh")) != -1) {
		switch (c) {
		case 'e':
			mode = ENCODE_FILE;
			break;
		case 'd':
			mode = DECODE_FILE;
			break;
		case 'D':
			mode = DECODE_STRING;
			break;
		case 'h':
			usage(argv[0], 0, NULL);
			break;
		default:
			usage(argv[0], 1, "Unknown command line argument");
			break;
		}
	}

	if (mode == ENCODE_NONE) {
		usage(argv[0], 1, "A mode of operation must be chosen.");
	}

	int retval;
	if (mode == ENCODE_FILE || mode == DECODE_FILE) {
		if (argc - optind > 1) {
			usage(argv[0], 1, "Too many args");
		}

		const char *binfile = (optind < argc) ? argv[optind] : "-";
		int d = strcmp(binfile, "-") == 0 ? STDIN_FILENO : open(binfile, O_RDONLY);
		if (d < 0) {
			err(1, "Failed to open %s: %s\n", binfile, strerror(errno));
		}
		struct stat st;
		memset(&st, 0, sizeof(st));
		if (fstat(d, &st) < 0 || st.st_size == 0) {
			st.st_size = 5 * 1024;  // multiple of 5 to avoid internal padding
			                        // AND multiple of 8 to ensure we feed
			                        //  valid data to base32_decode().
		}
		uint8_t *input = malloc(st.st_size + 1);
		int amt_read;
		int amt_to_read = st.st_size;
		errno = 0;
		while ((amt_read = read(d, input, amt_to_read)) > 0 || errno == EINTR) {
			if (errno == EINTR) {
				continue;
			}

			// Encoding: 8 bytes out for every 5 input, plus up to 6 padding, and nul
			// Decoding: up to 5 bytes out for every 8 input.
			int result_avail = (mode == ENCODE_FILE) ?
			                     ((amt_read + 4) / 5 * 8 + 6 + 1) :
			                     ((amt_read + 7) / 8 * 5) ;
			uint8_t *result = malloc(result_avail);

			input[amt_read] = '\0';

			if (mode == ENCODE_FILE) {
				retval = base32_encode(input, amt_read, result, result_avail, 1);
			} else {
				retval = base32_decode(input, result, result_avail);
			}
			if (retval < 0) {
				fprintf(stderr, "%s failed.  Input too long?\n", (mode == ENCODE_FILE) ? "base32_encode" : "base32_decode");
				exit(1);
			}
			//printf("%s", result);
			full_write(STDOUT_FILENO, result, retval);
			fflush(stdout);
			free(result);
		}
		if (amt_read < 0) {
			err(1, "Failed to read from %s: %s\n", binfile, strerror(errno));
		}
		if (mode == ENCODE_FILE) {
			printf("\n");
		}
	} else { // mode == DECODE_STRING
		if (argc - optind < 1) {
			usage(argv[0], 1, "Not enough args");
		}

		const char *base32_value = argv[2];
		int result_avail = strlen(base32_value) + 1;
		uint8_t *result = malloc(result_avail);

		retval = base32_decode((uint8_t *)base32_value, result, result_avail);
		if (retval < 0) {
			fprintf(stderr, "base32_decode failed.  Input too long?\n");
			exit(1);
		}
		full_write(STDOUT_FILENO, result, retval);
	}
	return 0;
}
