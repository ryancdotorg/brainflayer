#include <arpa/inet.h> // htonl/ntohl
#include <string.h> // memset/memcpy
#include <stdlib.h> // ssize_t
#include <stdint.h>

//#include "bech32.h"

static char b32t[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

uint32_t bech32_polymod(const unsigned char *buf, size_t sz) {
  uint32_t GEN[] = {0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3};
  uint32_t b, chk = 1;

  int i, j;
  for (i = 0; i < sz; ++i) {
    b = (chk >> 25);
    chk = (chk & 0x1ffffff) << 5 ^ buf[i];
    for (j = 0; j < 5; ++j) {
      if ((b >> j) & 1) {
        chk ^= GEN[j];
      }
    }
  }

  return chk;
}

/*  vim: set ts=2 sw=2 et ai si: */
