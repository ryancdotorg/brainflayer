#include <arpa/inet.h> // htonl/ntohl
#include <string.h> // memset/memcpy
#include <stdlib.h> // ssize_t
#include <stdint.h>

#include "../sha256/sha256.h"

#include "b58.h"

static char b58t[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
static signed char b58r[] = {-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,0,1,2,3,4,5,6,7,8,-1,-1,-1,-1,-1,-1,-1,
9,10,11,12,13,14,15,16,-1,17,18,19,20,21,-1,22,23,24,25,26,27,28,29,30,
31,32,-1,-1,-1,-1,-1,-1,33,34,35,36,37,38,39,40,41,42,43,-1,44,45,46,47,
48,49,50,51,52,53,54,55,56,57,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1};

void b58_csum(unsigned char out[4], const unsigned char *in, size_t in_sz) {
  unsigned char hash[SHA256_DIGEST_LENGTH];

  Hash256(hash, in, in_sz);

  memcpy(out, hash, 4);
}

int b58_csum_vrfy(const unsigned char chk[4], const unsigned char *in, size_t in_sz) {
  unsigned char hash[SHA256_DIGEST_LENGTH];

  Hash256(hash, in, in_sz);

  return memcmp(chk, hash, 4);
}

// ported from https://gist.github.com/diafygi/90a3e80ca1c2793220e5#file-annotated-js-L1
ssize_t b58e_raw(unsigned char *out, size_t out_sz, const unsigned char *in, size_t in_sz) {
  int d[256]; // b58 digits, reversed, negitive => undefined
  memset(d, -1, sizeof(d));
  int p = 0; // output position
  int i = 0; // byte iterator
  int j = 0; // b58 digit iterator
  int carry, n;

  // ensure we don't overflow the internal buffer
  if (out_sz > (sizeof(d)/sizeof(d[0]))) { out_sz = (sizeof(d)/sizeof(d[0])); }

  for (i = 0; i < in_sz; ++i) {
    j = 0;
    carry = in[i];
    // prepend "1" if zero byte and no non-zero bytes yet
    if (carry == 0 && p == i) { out[p++] = '1'; }

    while (d[j] >= 0 || carry) {
      n = d[j];
      n = n < 0 ? carry : n * 256 + carry;
      carry = n / 58;
      d[j++] = n % 58;
      if (j >= out_sz) { return -1; }
    }
  }

  while (j-- && p < out_sz) { out[p++] = b58t[d[j]]; }
  out[p] = 0; // null terminate
  return p; // return output size
}

// ported from https://gist.github.com/diafygi/90a3e80ca1c2793220e5#file-annotated-js-L29
ssize_t b58d_raw(unsigned char *out, size_t out_sz, const unsigned char *in, size_t in_sz) {
  int d[256]; // bytes, reversed, negitive => undefined
  memset(d, -1, sizeof(d));
  int p = 0; // output position
  int i = 0; // b58 digit iterator
  int j = 0; // byte iterator
  int carry, n;

  // ensure we don't overflow the internal buffer
  if (out_sz > (sizeof(d)/sizeof(d[0]))) { out_sz = (sizeof(d)/sizeof(d[0])); return -1; }

  for (i = 0; i < in_sz; ++i) {
    carry = b58r[in[i]];
    if (carry < 0) { return -2; }
    if (carry == 0 && p == i) { out[p++] = 0; }
    for (j = 0; d[j] >= 0 || carry;) {
      n = d[j];
      n = n >= 0 ? n * 58 + carry : carry;
      carry = n >> 8;
      d[j++] = n & 0xff;
      if (j > out_sz) { return -3; }
    }
  }

  while (j--) { out[p++] = d[j]; }
  return p; // return output size
}

ssize_t b58e_chk(unsigned char *out, size_t out_sz, const unsigned char *in, size_t in_sz, unsigned char ver) {
  unsigned char raw[256];

  if (in_sz > 160) { return -1; }
  raw[0] = ver;
  memcpy(raw+1, in, in_sz);
  b58_csum(raw+1+in_sz, raw, 1+in_sz);
  return b58e_raw(out, out_sz, raw, in_sz+5);
}

ssize_t b58d_chk(unsigned char *out, size_t out_sz, const unsigned char *in, size_t in_sz, unsigned char *ver) {
  unsigned char raw[256];
  ssize_t raw_sz;

  if (in_sz > 256) { return -1; }
  if ((raw_sz = b58d_raw(raw, sizeof(raw), in, in_sz)) < 5) { return -2; }
  *ver = raw[0];
  if (b58_csum_vrfy(raw+(raw_sz-4), raw, raw_sz-4) != 0) { return -3; }
  if (out_sz < raw_sz - 5) { return -4; }
  memcpy(out, raw+1, raw_sz-5);
  return raw_sz - 5;
}

ssize_t b58e_chkl(unsigned char *out, size_t out_sz, const unsigned char *in, size_t in_sz, uint32_t ver) {
  unsigned char raw[256];
  uint32_t tmp;

  if (in_sz > 160) { return -1; }
  tmp = htonl(ver);
  memcpy(raw, &tmp, 4);
  memcpy(raw+4, in, in_sz);
  b58_csum(raw+4+in_sz, raw, 4+in_sz);
  return b58e_raw(out, out_sz, raw, in_sz+8);
}

ssize_t b58d_chkl(unsigned char *out, size_t out_sz, const unsigned char *in, size_t in_sz, uint32_t *ver) {
  unsigned char raw[256];
  uint32_t tmp;
  ssize_t raw_sz;

  if (in_sz > 256) { return -1; }
  if ((raw_sz = b58d_raw(raw, sizeof(raw), in, in_sz)) < 8) { return -2; }
  memcpy(&tmp, raw, 4);
  *ver = ntohl(tmp);
  if (b58_csum_vrfy(raw+(raw_sz-4), raw, raw_sz-4) != 0) { return -3; }
  if (out_sz < raw_sz - 8) { return -1; }
  memcpy(out, raw+4, raw_sz-8);
  return raw_sz - 8;
}

/*  vim: set ts=2 sw=2 et ai si: */
