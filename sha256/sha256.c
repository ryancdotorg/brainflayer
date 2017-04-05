#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "sha256.h"

/* byte conversion */
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
# define be32(x) __builtin_bswap32(x)
# define be64(x) __builtin_bswap64(x)
#else
# define be32(x) (x)
# define be64(x) (x)
#endif

#include "ripemd160.c"

static void sha256_transform_internal(uint32_t *digest, const char *data, uint64_t nblk);

extern void sha256_transform_ssse3(uint32_t *digest, const char *data, uint64_t nblk);
extern void sha256_transform_avx(uint32_t *digest, const char *data, uint64_t nblk);
extern void sha256_transform_rorx(uint32_t *digest, const char *data, uint64_t nblk);
extern void sha256_ni_transform(uint32_t *digest, const char *data, uint64_t nblk);

extern int sha256_ssse3_built();
extern int sha256_avx_built();
extern int sha256_rorx_built();
extern int sha256_ni_built();

static void (*sha256_transform_func)(uint32_t *digest, const char *data, uint64_t nblk)=
  sha256_transform_internal;

/* static padding for 256 bit input */
static uint8_t rmd160_256[64] = {
  0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,

  0x80, 0x00, 0x00, 0x00,   0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,   0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,   0x00, 0x00, 0x00, 0x00,
  /* length 256 bits, little endian uint64_t */
  0x00, 0x01, 0x00, 0x00,   0x00, 0x00, 0x00, 0x00
};

static uint8_t input33[64] = {
  0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,

  0x00, 0x80, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
  /* length 264 bits, big endian uint64_t */
  0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x01, 0x08
};
void Hash160_33(uint8_t hash[], const uint8_t data[]) {
  int i;
  SHA2_256_CTX ctx;

  ctx.state[0]=0x6a09e667;
  ctx.state[1]=0xbb67ae85;
  ctx.state[2]=0x3c6ef372;
  ctx.state[3]=0xa54ff53a;
  ctx.state[4]=0x510e527f;
  ctx.state[5]=0x9b05688c;
  ctx.state[6]=0x1f83d9ab;
  ctx.state[7]=0x5be0cd19;

  memcpy(input33, data, 33);
  sha256_transform_func(ctx.state, input33, 1);

  for (i = 0; i < 8; ++i) ((uint32_t *)rmd160_256)[i] = be32(ctx.state[i]);
  ripemd160_rawcompress(rmd160_256, hash);
}

static uint8_t input65[128] = {
  0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,

  0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,

  0x00, 0x80, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,

  0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
  /* length 520 bits, big endian uint64_t */
  0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x02, 0x08
};
void Hash160_65(uint8_t hash[], const uint8_t data[]) {
  int i;
  SHA2_256_CTX ctx;

  ctx.state[0] = 0x6a09e667;
  ctx.state[1] = 0xbb67ae85;
  ctx.state[2] = 0x3c6ef372;
  ctx.state[3] = 0xa54ff53a;
  ctx.state[4] = 0x510e527f;
  ctx.state[5] = 0x9b05688c;
  ctx.state[6] = 0x1f83d9ab;
  ctx.state[7] = 0x5be0cd19;

  memcpy(input65, data, 65);
  sha256_transform_func(ctx.state, input65, 2);

  for (i = 0; i < 8; ++i) ((uint32_t *)rmd160_256)[i] = be32(ctx.state[i]);
  ripemd160_rawcompress(rmd160_256, hash);
}

void SHA2_256_Init(SHA2_256_CTX *ctx) {
  ctx->bitlen = 0;
  ctx->datalen = 0;
  ctx->state[0] = 0x6a09e667;
  ctx->state[1] = 0xbb67ae85;
  ctx->state[2] = 0x3c6ef372;
  ctx->state[3] = 0xa54ff53a;
  ctx->state[4] = 0x510e527f;
  ctx->state[5] = 0x9b05688c;
  ctx->state[6] = 0x1f83d9ab;
  ctx->state[7] = 0x5be0cd19;
}

void SHA2_256_Update(SHA2_256_CTX *ctx, const uint8_t data[], size_t len) {
  size_t i = 0;

  uint8_t *input = (uint8_t *)data;

  if (ctx->datalen > 0) {
    i = 64 - ctx->datalen;
    if (i > len) {
      memcpy(ctx->data + ctx->datalen, input, len);
      ctx->datalen += len;
      return;
    } else {
      memcpy(ctx->data + ctx->datalen, input, i);
      sha256_transform_func(ctx->state, ctx->data, 1);
      ctx->bitlen += 512;
      ctx->datalen = 0;
      input += i;
      len -= i;
    }
  }

  if (len >= 64) {
    i = len / 64;
    sha256_transform_func(ctx->state, input, i);
    len -= i * 64;
    input += i * 64;
    ctx->bitlen += i * 512;
  }

  memcpy(ctx->data, input, len);
  ctx->datalen = len;
}

void SHA2_256_Final(uint8_t hash[], SHA2_256_CTX *ctx) {
  uint32_t i = ctx->datalen;

  if (ctx->datalen < 56) {
    ctx->data[i++] = 0x80;
    memset(ctx->data + i, 0, 56 - i);
  } else {
    ctx->data[i++] = 0x80;
    memset(ctx->data + i, 0, 64 - i);
    sha256_transform_func(ctx->state, ctx->data, 1);
    memset(ctx->data, 0, 56);
  }

  // padding
  ctx->bitlen += ctx->datalen * 8;
  ((uint64_t *)ctx->data)[7] = be64(ctx->bitlen);

  sha256_transform_func(ctx->state, ctx->data, 1);

  ((uint32_t *)hash)[0] = be32(ctx->state[0]);
  ((uint32_t *)hash)[1] = be32(ctx->state[1]);
  ((uint32_t *)hash)[2] = be32(ctx->state[2]);
  ((uint32_t *)hash)[3] = be32(ctx->state[3]);
  ((uint32_t *)hash)[4] = be32(ctx->state[4]);
  ((uint32_t *)hash)[5] = be32(ctx->state[5]);
  ((uint32_t *)hash)[6] = be32(ctx->state[6]);
  ((uint32_t *)hash)[7] = be32(ctx->state[7]);
}

// caller responsible for making sure the buffer is big enough
uint64_t SHA2_256_Pad(uint8_t data[], size_t len) {
  uint64_t *bitlen_ptr;
  uint64_t nblk = len >> 6; // divide by 64, rounding down
  int remaining_bytes = len & 63;

  data[len] = 0x80;

  if (remaining_bytes < 56) {
    memset(data + len + 1, 0,  56 - (remaining_bytes + 1));
    bitlen_ptr = (uint64_t *)(data + (len & (UINT64_MAX ^ 64)) +  56);
    nblk += 1;
  } else {
    memset(data + len + 1, 0, 120 - (remaining_bytes + 1));
    bitlen_ptr = (uint64_t *)(data + (len & (UINT64_MAX ^ 64)) + 120);
    nblk += 2;
  }

  *bitlen_ptr = be64(len * 8);

  return nblk;
}

// caller is responsible for padding
void SHA2_256_Raw(uint8_t hash[], const uint8_t data[], uint64_t nblk) {
  uint32_t state[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
  };

  sha256_transform_func(state, data, nblk);

  ((uint32_t *)hash)[0] = be32(state[0]);
  ((uint32_t *)hash)[1] = be32(state[1]);
  ((uint32_t *)hash)[2] = be32(state[2]);
  ((uint32_t *)hash)[3] = be32(state[3]);
  ((uint32_t *)hash)[4] = be32(state[4]);
  ((uint32_t *)hash)[5] = be32(state[5]);
  ((uint32_t *)hash)[6] = be32(state[6]);
  ((uint32_t *)hash)[7] = be32(state[7]);
}

#include "sha256_xform.c"
#include "sha256_reg.c"
