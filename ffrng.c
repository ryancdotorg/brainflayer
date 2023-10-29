/* Copyright (c) 2015 Ryan Castellucci, All Rights Reserved */
#include <stdint.h>
#include <stddef.h>

#include "ffrng.h"

static const int64_t RNG_MULTIPLIER = 0x5DEECE66DLL;
static const int64_t RNG_ADDEND = 0xBLL;
static const int64_t RNG_MASK = (1LL << 48) - 1;
static const double  RNG_DSCALE = (double)(1LL << 53);

void ffrng_init(int64_t *ctx, int64_t seed) {
  *ctx = (seed ^ RNG_MULTIPLIER) & RNG_MASK;
}

uint64_t ffrng_next(int64_t *ctx, int bits) {
  uint64_t nextseed = *ctx * RNG_MULTIPLIER;
  nextseed += RNG_ADDEND;
  nextseed &= RNG_MASK;
  *ctx = nextseed;
  return nextseed >> (48 - bits);
}

double ffrng_double(int64_t *ctx) {
  double r = ((double)((ffrng_next(ctx, 26) << 27) + ffrng_next(ctx, 27))) / RNG_DSCALE;
  return r;
}

void ffrng_bytes(int64_t *ctx, unsigned char *buf, size_t buf_sz) {
  size_t i;
  for (i = 0; i < buf_sz; ++i) {
    buf[i] = (((double)256) * ffrng_double(ctx));
  }
}

/*
void ffrng_bytes_seed_o(unsigned char *buf, size_t buf_sz, int64_t seed) {
  int64_t ctx;
  ffrng_init(&ctx, seed);
  ffrng_bytes(&ctx, buf, buf_sz);
}
*/

void ffrng_bytes_seed(unsigned char *buf, size_t buf_sz, int64_t seed) {
  // the RNG_MASK step is not required here
  int64_t state = (seed ^ RNG_MULTIPLIER);// & RNG_MASK;
  for (int i = 0; i < buf_sz; ++i) {
    state *= RNG_MULTIPLIER;
    state += RNG_ADDEND;
    //state &= RNG_MASK;
    buf[i] = state >> 40;
    state *= RNG_MULTIPLIER;
    state += RNG_ADDEND;
    //state &= RNG_MASK;
  }
}
/* vim: set ts=2 sw=2 et ai si: */
