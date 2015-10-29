/* Copyright (c) 2015 Ryan Castellucci, All Rights Reserved */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

#include "hex.h"

unsigned char *
hex(unsigned char *buf, size_t buf_sz,
    unsigned char *hexed, size_t hexed_sz) {
  int i, j;
  --hexed_sz;
  for (i = j = 0; i < buf_sz && j < hexed_sz; ++i, j += 2) {
    snprintf(hexed+j, 3, "%02x", buf[i]);
  }
  hexed[j] = 0; // null terminate
  return hexed;
}

/*  vim: set ts=2 sw=2 et ai si: */
