#ifndef __SHA256_H_
#define __SHA256_H_

#include <stddef.h>
#include <stdint.h>

#define SHA256_DIGEST_LENGTH 32

#define SHA256_USING_SHAEXT   5
#define SHA256_USING_AVX2     4
#define SHA256_USING_AVX      3
#define SHA256_USING_SSSE3    2
#define SHA256_USING_INTERNAL 1

typedef struct {
  uint8_t data[64];
  uint64_t bitlen;
  uint32_t state[8];
  uint32_t datalen;
} SHA2_256_CTX;

int SHA2_256_Register();

void SHA2_256_Init(SHA2_256_CTX *ctx);
void SHA2_256_Update(SHA2_256_CTX *ctx, const uint8_t data[], size_t len);
void SHA2_256_Final(uint8_t hash[], SHA2_256_CTX *ctx);

uint64_t SHA2_256_Pad(uint8_t data[], size_t len);
void SHA2_256_Raw(uint8_t hash[], const uint8_t data[], uint64_t nblk);

void Hash160_Raw(uint8_t hash[], const uint8_t data[], uint64_t nblk);
void Hash160_25(uint8_t hash[], const uint8_t data[]);
void Hash160_33(uint8_t hash[], const uint8_t data[]);
void Hash160_35(uint8_t hash[], const uint8_t data[]);
void Hash160_37(uint8_t hash[], const uint8_t data[]);
void Hash160_65(uint8_t hash[], const uint8_t data[]);
void Hash160_67(uint8_t hash[], const uint8_t data[]);
void Hash160_69(uint8_t hash[], const uint8_t data[]);

#endif//__SHA256_H_
