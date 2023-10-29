#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <endian.h>

#include <sys/random.h>

#include "sha256.h"

void SHA2_256_Serialize(void *hash, uint32_t state[8]) {
  ((uint32_t *)hash)[0] = htobe32(state[0]);
  ((uint32_t *)hash)[1] = htobe32(state[1]);
  ((uint32_t *)hash)[2] = htobe32(state[2]);
  ((uint32_t *)hash)[3] = htobe32(state[3]);
  ((uint32_t *)hash)[4] = htobe32(state[4]);
  ((uint32_t *)hash)[5] = htobe32(state[5]);
  ((uint32_t *)hash)[6] = htobe32(state[6]);
  ((uint32_t *)hash)[7] = htobe32(state[7]);
}

#define CHARS 32

int main() {
  int i;

  uint32_t iv[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
  };

  uint32_t S[8];

  unsigned char hash0[32];

  unsigned char buf[64];
  if (getrandom(buf, CHARS, 0) <= 0) { return -1; }
  SHA2_256_Pad(buf, CHARS);

  for (i = 0; i < CHARS; ++i) {
    buf[i] = (buf[i] & 0x7f);
    if (buf[i] < 33) { buf[i] = buf[i] * 2 + 33; }
    if (buf[i] > 0x7f) { buf[i] = 126; }
  }

  SHA2_256_Register(-1);

  ssize_t iter = 0;
  while (iter < 100000000) {
    i = CHARS - 1;
    while (i >= 0) {
      if (buf[i] == 126) {
        buf[i--] = 33;
      } else {
        buf[i]++;
        break;
      }
    }

    memcpy(S, iv, 32);
    SHA2_256_Transform(S, buf, 1);

    if (S[0] == 0xffffffff) {
      break;
    }
    ++iter;
  }

  SHA2_256_Serialize(hash0, S);

  buf[CHARS] = 0;
  printf("%zu %s\n", iter, buf);
  for (i = 0; i < 32; ++i) {
    printf("%02x", hash0[i]);
  }
  printf("\n");

  return 0;
}

/*  vim: set ts=2 sw=2 et ai si: */
