/*
 * Copyright 2010 Google Inc.
 * Author: Markus Gutschke
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 *
 * An earlier version of this file was originally released into the public
 * domain by its authors. It has been modified to make the code compile and
 * link as part of the Google Authenticator project. These changes are
 * copyrighted by Google Inc. and released under the Apache License,
 * Version 2.0.
 *
 * The previous authors' terms are included below:
 */

/*****************************************************************************
 *
 * File:    sha1.c
 *
 * Purpose: Implementation of the SHA1 message-digest algorithm.
 *
 * NIST Secure Hash Algorithm
 *   Heavily modified by Uwe Hollerbach <uh@alumni.caltech edu>
 *   from Peter C. Gutmann's implementation as found in
 *   Applied Cryptography by Bruce Schneier
 *   Further modifications to include the "UNRAVEL" stuff, below
 *
 * This code is in the public domain
 *
 *****************************************************************************
*/
#define _BSD_SOURCE
#include <sys/types.h> // Defines BYTE_ORDER, iff _BSD_SOURCE is defined
#include <string.h>

#include "sha1.h"

#if !defined(BYTE_ORDER)
#if defined(_BIG_ENDIAN)
#define BYTE_ORDER 4321
#elif defined(_LITTLE_ENDIAN)
#define BYTE_ORDER 1234
#else
#error Need to define BYTE_ORDER
#endif
#endif

#ifndef TRUNC32
  #define TRUNC32(x)  ((x) & 0xffffffffL)
#endif

/* SHA f()-functions */
#define f1(x,y,z)    ((x & y) | (~x & z))
#define f2(x,y,z)    (x ^ y ^ z)
#define f3(x,y,z)    ((x & y) | (x & z) | (y & z))
#define f4(x,y,z)    (x ^ y ^ z)

/* SHA constants */
#define CONST1        0x5a827999L
#define CONST2        0x6ed9eba1L
#define CONST3        0x8f1bbcdcL
#define CONST4        0xca62c1d6L

/* truncate to 32 bits -- should be a null op on 32-bit machines */
#define T32(x)    ((x) & 0xffffffffL)

/* 32-bit rotate */
#define R32(x,n)    T32(((x << n) | (x >> (32 - n))))

/* the generic case, for when the overall rotation is not unraveled */
#define FG(n)    \
    T = T32(R32(A,5) + f##n(B,C,D) + E + *WP++ + CONST##n);    \
    E = D; D = C; C = R32(B,30); B = A; A = T

/* specific cases, for when the overall rotation is unraveled */
#define FA(n)    \
    T = T32(R32(A,5) + f##n(B,C,D) + E + *WP++ + CONST##n); B = R32(B,30)

#define FB(n)    \
    E = T32(R32(T,5) + f##n(A,B,C) + D + *WP++ + CONST##n); A = R32(A,30)

#define FC(n)    \
    D = T32(R32(E,5) + f##n(T,A,B) + C + *WP++ + CONST##n); T = R32(T,30)

#define FD(n)    \
    C = T32(R32(D,5) + f##n(E,T,A) + B + *WP++ + CONST##n); E = R32(E,30)

#define FE(n)    \
    B = T32(R32(C,5) + f##n(D,E,T) + A + *WP++ + CONST##n); D = R32(D,30)

#define FT(n)    \
    A = T32(R32(B,5) + f##n(C,D,E) + T + *WP++ + CONST##n); C = R32(C,30)


static void
sha1_transform(SHA1_INFO *sha1_info)
{
    int i;
    uint8_t *dp;
    uint32_t T, A, B, C, D, E, W[80], *WP;

    dp = sha1_info->data;

#undef SWAP_DONE

#if BYTE_ORDER == 1234
#define SWAP_DONE
    for (i = 0; i < 16; ++i) {
        T = *((uint32_t *) dp);
        dp += 4;
        W[i] = 
            ((T << 24) & 0xff000000) |
            ((T <<  8) & 0x00ff0000) |
            ((T >>  8) & 0x0000ff00) | ((T >> 24) & 0x000000ff);
    }
#endif

#if BYTE_ORDER == 4321
#define SWAP_DONE
    for (i = 0; i < 16; ++i) {
        T = *((uint32_t *) dp);
        dp += 4;
        W[i] = TRUNC32(T);
    }
#endif

#if BYTE_ORDER == 12345678
#define SWAP_DONE
    for (i = 0; i < 16; i += 2) {
        T = *((uint32_t *) dp);
        dp += 8;
        W[i] =  ((T << 24) & 0xff000000) | ((T <<  8) & 0x00ff0000) |
            ((T >>  8) & 0x0000ff00) | ((T >> 24) & 0x000000ff);
        T >>= 32;
        W[i+1] = ((T << 24) & 0xff000000) | ((T <<  8) & 0x00ff0000) |
            ((T >>  8) & 0x0000ff00) | ((T >> 24) & 0x000000ff);
    }
#endif

#if BYTE_ORDER == 87654321
#define SWAP_DONE
    for (i = 0; i < 16; i += 2) {
        T = *((uint32_t *) dp);
        dp += 8;
        W[i] = TRUNC32(T >> 32);
        W[i+1] = TRUNC32(T);
    }
#endif

#ifndef SWAP_DONE
#define SWAP_DONE
    for (i = 0; i < 16; ++i) {
        T = *((uint32_t *) dp);
        dp += 4;
        W[i] = TRUNC32(T);
    }
#endif /* SWAP_DONE */

    for (i = 16; i < 80; ++i) {
    W[i] = W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16];
    W[i] = R32(W[i], 1);
    }
    A = sha1_info->digest[0];
    B = sha1_info->digest[1];
    C = sha1_info->digest[2];
    D = sha1_info->digest[3];
    E = sha1_info->digest[4];
    WP = W;
#ifdef UNRAVEL
    FA(1); FB(1); FC(1); FD(1); FE(1); FT(1); FA(1); FB(1); FC(1); FD(1);
    FE(1); FT(1); FA(1); FB(1); FC(1); FD(1); FE(1); FT(1); FA(1); FB(1);
    FC(2); FD(2); FE(2); FT(2); FA(2); FB(2); FC(2); FD(2); FE(2); FT(2);
    FA(2); FB(2); FC(2); FD(2); FE(2); FT(2); FA(2); FB(2); FC(2); FD(2);
    FE(3); FT(3); FA(3); FB(3); FC(3); FD(3); FE(3); FT(3); FA(3); FB(3);
    FC(3); FD(3); FE(3); FT(3); FA(3); FB(3); FC(3); FD(3); FE(3); FT(3);
    FA(4); FB(4); FC(4); FD(4); FE(4); FT(4); FA(4); FB(4); FC(4); FD(4);
    FE(4); FT(4); FA(4); FB(4); FC(4); FD(4); FE(4); FT(4); FA(4); FB(4);
    sha1_info->digest[0] = T32(sha1_info->digest[0] + E);
    sha1_info->digest[1] = T32(sha1_info->digest[1] + T);
    sha1_info->digest[2] = T32(sha1_info->digest[2] + A);
    sha1_info->digest[3] = T32(sha1_info->digest[3] + B);
    sha1_info->digest[4] = T32(sha1_info->digest[4] + C);
#else /* !UNRAVEL */
#ifdef UNROLL_LOOPS
    FG(1); FG(1); FG(1); FG(1); FG(1); FG(1); FG(1); FG(1); FG(1); FG(1);
    FG(1); FG(1); FG(1); FG(1); FG(1); FG(1); FG(1); FG(1); FG(1); FG(1);
    FG(2); FG(2); FG(2); FG(2); FG(2); FG(2); FG(2); FG(2); FG(2); FG(2);
    FG(2); FG(2); FG(2); FG(2); FG(2); FG(2); FG(2); FG(2); FG(2); FG(2);
    FG(3); FG(3); FG(3); FG(3); FG(3); FG(3); FG(3); FG(3); FG(3); FG(3);
    FG(3); FG(3); FG(3); FG(3); FG(3); FG(3); FG(3); FG(3); FG(3); FG(3);
    FG(4); FG(4); FG(4); FG(4); FG(4); FG(4); FG(4); FG(4); FG(4); FG(4);
    FG(4); FG(4); FG(4); FG(4); FG(4); FG(4); FG(4); FG(4); FG(4); FG(4);
#else /* !UNROLL_LOOPS */
    for (i =  0; i < 20; ++i) { FG(1); }
    for (i = 20; i < 40; ++i) { FG(2); }
    for (i = 40; i < 60; ++i) { FG(3); }
    for (i = 60; i < 80; ++i) { FG(4); }
#endif /* !UNROLL_LOOPS */
    sha1_info->digest[0] = T32(sha1_info->digest[0] + A);
    sha1_info->digest[1] = T32(sha1_info->digest[1] + B);
    sha1_info->digest[2] = T32(sha1_info->digest[2] + C);
    sha1_info->digest[3] = T32(sha1_info->digest[3] + D);
    sha1_info->digest[4] = T32(sha1_info->digest[4] + E);
#endif /* !UNRAVEL */
}

/* initialize the SHA digest */

void
sha1_init(SHA1_INFO *sha1_info)
{
    sha1_info->digest[0] = 0x67452301L;
    sha1_info->digest[1] = 0xefcdab89L;
    sha1_info->digest[2] = 0x98badcfeL;
    sha1_info->digest[3] = 0x10325476L;
    sha1_info->digest[4] = 0xc3d2e1f0L;
    sha1_info->count_lo = 0L;
    sha1_info->count_hi = 0L;
    sha1_info->local = 0;
}

/* update the SHA digest */

void
sha1_update(SHA1_INFO *sha1_info, const uint8_t *buffer, int count)
{
    int i;
    uint32_t clo;

    clo = T32(sha1_info->count_lo + ((uint32_t) count << 3));
    if (clo < sha1_info->count_lo) {
    ++sha1_info->count_hi;
    }
    sha1_info->count_lo = clo;
    sha1_info->count_hi += (uint32_t) count >> 29;
    if (sha1_info->local) {
    i = SHA1_BLOCKSIZE - sha1_info->local;
    if (i > count) {
        i = count;
    }
    memcpy(((uint8_t *) sha1_info->data) + sha1_info->local, buffer, i);
    count -= i;
    buffer += i;
    sha1_info->local += i;
    if (sha1_info->local == SHA1_BLOCKSIZE) {
        sha1_transform(sha1_info);
    } else {
        return;
    }
    }
    while (count >= SHA1_BLOCKSIZE) {
    memcpy(sha1_info->data, buffer, SHA1_BLOCKSIZE);
    buffer += SHA1_BLOCKSIZE;
    count -= SHA1_BLOCKSIZE;
    sha1_transform(sha1_info);
    }
    memcpy(sha1_info->data, buffer, count);
    sha1_info->local = count;
}


static void
sha1_transform_and_copy(unsigned char digest[20], SHA1_INFO *sha1_info)
{
    sha1_transform(sha1_info);
    digest[ 0] = (unsigned char) ((sha1_info->digest[0] >> 24) & 0xff);
    digest[ 1] = (unsigned char) ((sha1_info->digest[0] >> 16) & 0xff);
    digest[ 2] = (unsigned char) ((sha1_info->digest[0] >>  8) & 0xff);
    digest[ 3] = (unsigned char) ((sha1_info->digest[0]      ) & 0xff);
    digest[ 4] = (unsigned char) ((sha1_info->digest[1] >> 24) & 0xff);
    digest[ 5] = (unsigned char) ((sha1_info->digest[1] >> 16) & 0xff);
    digest[ 6] = (unsigned char) ((sha1_info->digest[1] >>  8) & 0xff);
    digest[ 7] = (unsigned char) ((sha1_info->digest[1]      ) & 0xff);
    digest[ 8] = (unsigned char) ((sha1_info->digest[2] >> 24) & 0xff);
    digest[ 9] = (unsigned char) ((sha1_info->digest[2] >> 16) & 0xff);
    digest[10] = (unsigned char) ((sha1_info->digest[2] >>  8) & 0xff);
    digest[11] = (unsigned char) ((sha1_info->digest[2]      ) & 0xff);
    digest[12] = (unsigned char) ((sha1_info->digest[3] >> 24) & 0xff);
    digest[13] = (unsigned char) ((sha1_info->digest[3] >> 16) & 0xff);
    digest[14] = (unsigned char) ((sha1_info->digest[3] >>  8) & 0xff);
    digest[15] = (unsigned char) ((sha1_info->digest[3]      ) & 0xff);
    digest[16] = (unsigned char) ((sha1_info->digest[4] >> 24) & 0xff);
    digest[17] = (unsigned char) ((sha1_info->digest[4] >> 16) & 0xff);
    digest[18] = (unsigned char) ((sha1_info->digest[4] >>  8) & 0xff);
    digest[19] = (unsigned char) ((sha1_info->digest[4]      ) & 0xff);
}

/* finish computing the SHA digest */
void
sha1_final(SHA1_INFO *sha1_info, uint8_t digest[20])
{
    int count;
    uint32_t lo_bit_count, hi_bit_count;

    lo_bit_count = sha1_info->count_lo;
    hi_bit_count = sha1_info->count_hi;
    count = (int) ((lo_bit_count >> 3) & 0x3f);
    ((uint8_t *) sha1_info->data)[count++] = 0x80;
    if (count > SHA1_BLOCKSIZE - 8) {
    memset(((uint8_t *) sha1_info->data) + count, 0, SHA1_BLOCKSIZE - count);
    sha1_transform(sha1_info);
    memset((uint8_t *) sha1_info->data, 0, SHA1_BLOCKSIZE - 8);
    } else {
    memset(((uint8_t *) sha1_info->data) + count, 0,
        SHA1_BLOCKSIZE - 8 - count);
    }
    sha1_info->data[56] = (uint8_t)((hi_bit_count >> 24) & 0xff);
    sha1_info->data[57] = (uint8_t)((hi_bit_count >> 16) & 0xff);
    sha1_info->data[58] = (uint8_t)((hi_bit_count >>  8) & 0xff);
    sha1_info->data[59] = (uint8_t)((hi_bit_count >>  0) & 0xff);
    sha1_info->data[60] = (uint8_t)((lo_bit_count >> 24) & 0xff);
    sha1_info->data[61] = (uint8_t)((lo_bit_count >> 16) & 0xff);
    sha1_info->data[62] = (uint8_t)((lo_bit_count >>  8) & 0xff);
    sha1_info->data[63] = (uint8_t)((lo_bit_count >>  0) & 0xff);
    sha1_transform_and_copy(digest, sha1_info);
}

/***EOF***/
