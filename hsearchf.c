/* Copyright (c) 2015 Ryan Castellucci, All Rights Reserved */
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include <arpa/inet.h> /*  for ntohl/htonl */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "hex.h"
#include "hash160.h"
#include "hsearchf.h"

#define HSEARCHF_DEBUG 0

#define HASHLEN RIPEMD160_DIGEST_LENGTH

#define RESULT(R) do { \
  res = R; \
  goto hsearchf_result; \
} while (0)

#define DO_MEMCMP(H) memcmp(H.uc, hash->uc, HASHLEN)

// use fadvise to do a readbehind
#define READ_AT(X, H) do { \
  posix_fadvise(fileno(f), ((X*HASHLEN)&0xfffff000)-4096, 8192, POSIX_FADV_WILLNEED); \
  if ((ret = fseek(f, X * HASHLEN, 0)) != 0) { return -1; } \
  if ((ret = fread(H.uc, HASHLEN, 1, f)) != 1) { return -1; } \
  ++i; \
} while (0)

// interpolation search
int hsearchf(FILE *f, hash160_t *hash) {
  int ret, res = 0, i = 0;
  size_t file_sz;
  struct stat sb;
  hash160_t low_h, mid_h, high_h;
  int64_t low_e, mid_e, high_e, entries;
  int64_t vlow, vhigh, vtarget;

#if HSEARCHF_DEBUG > 0
  unsigned char hexed[64];
#endif

  if ((ret = fstat(fileno(f), &sb)) != 0) { return -1; }
  file_sz = sb.st_size;
  entries = file_sz / HASHLEN;
  low_e = 0;
  high_e = entries - 1;

  vtarget = ntohl(hash->ul[0]);
  memset(low_h.uc, 0x00, HASHLEN);
  memset(high_h.uc, 0xff, HASHLEN);

  // this tries to minimize reads, but does a few extra comparisons
  while (low_e != high_e &&
         memcmp(hash->uc, low_h.uc, HASHLEN) > 0 &&
         memcmp(hash->uc, high_h.uc, HASHLEN) < 0) {
    vlow = ntohl(low_h.ul[0]); vhigh = ntohl(high_h.ul[0]);
    mid_e = low_e + (vtarget - vlow) * (high_e - low_e) / (vhigh - vlow);
    READ_AT(mid_e, mid_h);
    ret = DO_MEMCMP(mid_h);

#if HSEARCHF_DEBUG > 1
    fprintf(stderr, "target %s checking %9jd %9jd %9jd",
        hex(hash->uc, HASHLEN, hexed, sizeof(hexed)), low_e, mid_e, high_e);
    fprintf(stderr, " got %s %11d %2d\n",
        hex(mid_h.uc, HASHLEN, hexed, sizeof(hexed)), ret, i);
#endif

    if (ret == 0) {
      RESULT(1);
    } else if (ret < 0) {
      low_e = mid_e + 1;
      READ_AT(low_e, low_h);
      if (DO_MEMCMP(low_h) == 0) { RESULT(1); }
    } else { // ret > 0
      high_e = mid_e - 1;
      READ_AT(high_e, high_h);
      if (DO_MEMCMP(high_h) == 0) { RESULT(1); }
    }
  }

hsearchf_result:
#if HSEARCHF_DEBUG > 0
  fprintf(stderr, "target: %s reads: %3d result: %d\n", hex(hash->uc, HASHLEN, hexed, sizeof(hexed)), i, res);
#endif
  return res;
}

/* vim: set ts=2 sw=2 et ai si: */
