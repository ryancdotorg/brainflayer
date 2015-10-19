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

#define HASHLEN RIPEMD160_DIGEST_LENGTH

//#define USE_FUDGE

#define DO_MEMCMP() memcmp(candidate.uc, hash->uc, HASHLEN)

#define MAKE_GUESS(F) do { \
  guess = entries * (ntohl(hash->ul[0]) / 4294967296.0 + (F)); \
} while (0)

#define READ_AT(X) do { \
  if ((ret = fseek(f, (X) * HASHLEN, 0)) != 0) { return -1; } \
  if ((ret = fread(candidate.uc, HASHLEN, 1, f)) != 1) { return -1; } \
} while (0)

// could mmapf and use bsearch, but meh
int hsearchf(FILE *f, hash160_t *hash) {
  int ret;
  //int i = 0;
  size_t file_sz;
  struct stat sb;
  hash160_t candidate;
  //unsigned char hexed[64];
  int first, middle, last, entries;

  if ((ret = fstat(fileno(f), &sb)) != 0) { return -1; }
  file_sz = sb.st_size;
  entries = file_sz / HASHLEN;
  first = 0;
  last = entries - 1;

#ifdef USE_FUDGE
  // Most of the time, this is able to eliminate about nine reads because
  // the values are fairly uniform. Worst case, we make two extra reads, so
  // this is a win so long as it works at least a quarter of the time.
  // Playing with the denominators on the MAKE_GUESS macros may give slight
  // improvements.
  int guess;
  // make an initial guess at the location of the hash based on the target
  MAKE_GUESS(1.0/+2048);
  READ_AT(guess);
  //fprintf(stderr, "entries %10u guess %9u %s\n", hash->ul[0], guess, hex(candidate.uc, HASHLEN, hexed, sizeof(hexed)));
  ret = DO_MEMCMP();

  if (ret == 0) {
    return 1; // unlikely
  } else if (ret < 0) {
    first = guess;
    MAKE_GUESS(1.0/+1024);
    if (guess < entries) {
      READ_AT(guess);
      if (DO_MEMCMP() > 0) { last = guess; }
    }
  } else { // ret > 0
    last = guess;
    MAKE_GUESS(1.0/-32768);
    if (guess > 0) {
      READ_AT(guess);
      if (DO_MEMCMP() < 0) { first = guess; }
    }
  }
#endif

  middle = (first + last) / 2;

  // binary search
  while (first <= last) {
    //fprintf(stderr, "target %s, checking entry %9u", hex(hash->uc, HASHLEN, hexed, sizeof(hexed)), middle);
    READ_AT(middle);
    ret = DO_MEMCMP();
    //fprintf(stderr, " got %s %11d %2d\n", hex(candidate.uc, HASHLEN, hexed, sizeof(hexed)), ret, ++i);

    if (ret == 0) {
      return 1;
    } else if (ret < 0) {
      first = middle + 1;
    } else { // ret > 0
      last = middle - 1;
    }

    middle = (first + last) / 2;
  }

  return 0;
}

/* vim: set ts=2 sw=2 et ai si: */
