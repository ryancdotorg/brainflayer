#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <endian.h>
#include <stdio.h>

#include "sha256.h"

static unsigned char pad768[] = {
  0x80, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
  /* length 768 bits, big endian uint64_t */
  0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x03, 0x00
};

void HMAC_SHA2_256_Clone(HMAC_SHA2_256_CTX *dst, const HMAC_SHA2_256_CTX *src) {
  // relies on .data being first
  if (src->datalen) {
    memcpy(dst, src, sizeof(dst));
  } else {
    memcpy(dst + sizeof(dst->data), src + sizeof(dst->data), sizeof(dst) - sizeof(dst->data));
  }
}

void HMAC_SHA2_256_Init(HMAC_SHA2_256_CTX *ctx, const void *key, size_t len) {
  uint8_t *hash = ctx->hmac + 64;

  SHA2_256_Init((SHA2_256_CTX*)ctx);
  memset(ctx->hmac, 0, sizeof(ctx->hmac));

  if (len > 64) {
    SHA2_256(hash, key, len);
  } else {
    memcpy(hash, key, len);
  }

  for (int i = 0; i < 64; ++i) {
    ctx->hmac[i] = 0x5c ^ hash[i]; // opad
    hash[i] ^= 0x36;               // ipad
  }

  ctx->bitlen = 512;
  SHA2_256_Transform(ctx->state, hash, 1);
  memcpy(ctx->hmac + 96, pad768, 32);
}

void HMAC_SHA2_256_Update(HMAC_SHA2_256_CTX *ctx, const uint8_t data[], size_t len) {
  SHA2_256_Update((SHA2_256_CTX*)ctx, data, len);
}

void HMAC_SHA2_256_Final(uint8_t hash[], HMAC_SHA2_256_CTX *ctx) {
  SHA2_256_Final(ctx->hmac + 64, (SHA2_256_CTX*)ctx);
  SHA2_256_Raw(hash, ctx->hmac, 2);
}

void HMAC_SHA2_256(uint8_t hash[], const uint8_t key[], size_t key_sz, const uint8_t msg[], size_t msg_sz) {
  HMAC_SHA2_256_CTX ctx;

  HMAC_SHA2_256_Init(&ctx, key, key_sz);
  HMAC_SHA2_256_Update(&ctx, msg, msg_sz);
  HMAC_SHA2_256_Final(hash, &ctx);
}

void PBKDF2_HMAC_SHA2_256(
uint8_t dk[], size_t dk_sz,
const uint8_t pass[], size_t pass_sz,
const uint8_t salt[], size_t salt_sz,
int c) {
  HMAC_SHA2_256_CTX ctx, pctx;

  HMAC_SHA2_256_Init(&pctx, pass, pass_sz);

  int i, j, nout = 0, block = 1;
  uint8_t T[32];
  uint8_t U[32];

  uint8_t I_BE[4];

  while (nout < dk_sz) {
    *((uint32_t*)I_BE) = be32toh(block);
    HMAC_SHA2_256_Clone(&ctx, &pctx);
    HMAC_SHA2_256_Update(&ctx, salt, salt_sz);
    HMAC_SHA2_256_Update(&ctx, I_BE, sizeof(I_BE));
    HMAC_SHA2_256_Final(U, &ctx);
    memcpy(T, U, sizeof(T));
    for (i = 1; i < c; ++i) {
      HMAC_SHA2_256_Clone(&ctx, &pctx);
      HMAC_SHA2_256_Update(&ctx, U, sizeof(U));
      HMAC_SHA2_256_Final(U, &ctx);
      for (j = 0; j < sizeof(T); ++j) { T[j] ^= U[j]; }
    }
    for (i = 0; nout < dk_sz && i < sizeof(T); ++i, ++nout) {
      dk[nout] = T[i];
    }
    ++block;
  }
}
