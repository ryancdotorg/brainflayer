#ifndef __SHA256_H_
#define __SHA256_H_

#include <stddef.h>
#include <stdint.h>

#define SHA256_DIGEST_LENGTH   32

#define SHA256_ERROR_UNAVAL    -3
#define SHA256_ERROR_NOSUPPORT -2
#define SHA256_ERROR_NOTBUILT  -1

#define SHA256_USING_INTERNAL   0
#define SHA256_USING_NAYUKI64   1
#define SHA256_USING_SSSE3      2
#define SHA256_USING_AVX        3
#define SHA256_USING_AVX2       4
#define SHA256_USING_SHAEXT     5

#define SHA256_ENABLE_NAYUKI64 (1<<SHA256_USING_NAYUKI64)
#define SHA256_ENABLE_SSSE3    (1<<SHA256_USING_SSSE3)
#define SHA256_ENABLE_AVX      (1<<SHA256_USING_AVX)
#define SHA256_ENABLE_AVX2     (1<<SHA256_USING_AVX2)
#define SHA256_ENABLE_SHAEXT   (1<<SHA256_USING_SHAEXT)

#define SHA256_DESC_INTERNAL   "Hashdeep (C)"
#define SHA256_DESC_NAYUKI64   "Nayuki (x64 asm)"
#define SHA256_DESC_SSSE3      "Intel SSSE3 (x64 asm)"
#define SHA256_DESC_AVX        "Intel AVX (x64 asm)"
#define SHA256_DESC_AVX2       "Intel AVX2 (x64 asm)"
#define SHA256_DESC_SHAEXT     "Intel SHA-NI (x64 asm)"

void (*SHA2_256_Transform)(uint32_t *digest, const char *data, uint32_t nblk);

void (*ripemd160_xform_func)(uint32_t *digest, const char *data);

typedef struct {
  uint8_t data[64];
  uint64_t bitlen;
  uint32_t state[8];
  uint32_t datalen;
} SHA2_256_CTX;

typedef struct {
  uint8_t data[64];
  uint64_t bitlen;
  uint32_t state[8];
  uint32_t datalen;
  uint8_t hmac[128];
} HMAC_SHA2_256_CTX;

char * SHA2_256_Describe(int impl);
int SHA2_256_Register(int enable);

void SHA2_256_Init(SHA2_256_CTX *ctx);
void SHA2_256_Update(SHA2_256_CTX *ctx, const uint8_t data[], size_t len);
void SHA2_256_Final(uint8_t hash[], SHA2_256_CTX *ctx);
void SHA2_256(uint8_t hash[], const uint8_t data[], size_t len);

uint64_t SHA2_256_Pad(uint8_t data[], size_t len);
void SHA2_256_Raw(uint8_t hash[], const uint8_t data[], uint64_t nblk);

void Hash256(uint8_t hash[], const uint8_t data[], size_t len);
void Hash256_Raw(uint8_t hash[], const uint8_t data[], uint64_t nblk);

void Hash160(uint8_t hash[], const uint8_t data[], size_t len);
void Hash160_Raw(uint8_t hash[], const uint8_t data[], uint64_t nblk);
void Hash160_22(uint8_t hash[], const uint8_t data[]);
void Hash160_25(uint8_t hash[], const uint8_t data[]);
void Hash160_33(uint8_t hash[], const uint8_t data[]);
void Hash160_35(uint8_t hash[], const uint8_t data[]);
void Hash160_37(uint8_t hash[], const uint8_t data[]);
void Hash160_65(uint8_t hash[], const uint8_t data[]);
void Hash160_67(uint8_t hash[], const uint8_t data[]);
void Hash160_69(uint8_t hash[], const uint8_t data[]);

#endif//__SHA256_H_
