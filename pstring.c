/* Copyright (c) 2015 Ryan Castellucci, All Rights Reserved */
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include "pstring.h"

/*   byte conversion */
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
# define le16(x) (x)
#else
# define le16(x) ( ( (x<<8) | ((x>>8)&255) ) & 65535 )
#endif

int pfread8(void *buf, FILE *f) {
  size_t r;
  uint8_t sz;
  if ((r = fread(&sz,  1, 1, f)) != 1) { return -1; }
  if ((r = fread(buf, sz, 1, f)) != 1) { return -1; }
  return sz;
}

int pfread16(void *buf, FILE *f) {
  size_t r;
  uint16_t sz;
  if ((r = fread(&sz,  2, 1, f)) != 1) { return -1; }
  if ((r = fread(buf, sz, 1, f)) != 1) { return -1; }
  return sz;
}

int pfwrite8(const void *buf, uint8_t sz, FILE *f) {
  size_t r;
  if ((r = fwrite(&sz,  1, 1, f)) != 1) { return -1; }
  if ((r = fwrite(buf, sz, 1, f)) != 1) { return -1; }
  return sz;
}

int pfwrite16(const void *buf, uint16_t sz, FILE *f) {
  size_t r;
  if ((r = fwrite(&sz,  2, 1, f)) != 1) { return -1; }
  if ((r = fwrite(buf, sz, 1, f)) != 1) { return -1; }
  return sz;
}

/*  vim: set ts=2 sw=2 et ai si: */
