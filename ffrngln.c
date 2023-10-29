/* Copyright (c) 2015 Ryan Castellucci, All Rights Reserved */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>

#include "ffrng.h"
#include "hex.h"

int main(int argc, char **argv) {
  unsigned char rngbytes[65536];
  unsigned char hexed[65];
  int64_t seed, seed_min, seed_max; 
  uint32_t offset, offset_min, offset_max;
  uint32_t seed_skip, offset_skip;

  if (argc < 5) {
    fprintf(stderr, "Usage: %s seed_min seed_max seed_skip offset_min offset_max offset_skip\n", argv[0]);
    return 1;
  }

  seed_min =    strtoll(argv[1], NULL, 10);
  seed_max =    strtoll(argv[2], NULL, 10);
  seed_skip =   strtoul(argv[3], NULL, 10);
  offset_min =  strtoul(argv[4], NULL, 10);
  offset_max =  strtoul(argv[5], NULL, 10);
  offset_skip = strtoul(argv[6], NULL, 10);

  for (seed = seed_min; seed <= seed_max; seed += seed_skip) {
    ffrng_bytes_seed(rngbytes, 32 + offset_max, seed);
    for (offset = offset_min; offset <= offset_max; offset += offset_skip) {
      printf("%s%016jx%04x\n", hex(rngbytes + offset, 32, hexed, 64), seed, offset);
    }
  }

  return 0;
}

/*  vim: set ts=2 sw=2 et ai si: */
