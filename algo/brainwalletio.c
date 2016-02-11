/* Copyright (c) 2015 Ryan Castellucci, All Rights Reserved */
#include <time.h>
#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>

#include <openssl/evp.h>
#include <openssl/sha.h>
// crypto.h used for the version
#include <openssl/crypto.h>

#include "../scrypt-jane/scrypt-jane.h"

#include "../hex.h"

#define _SCRYPT_N (1<<18)
#define _SCRYPT_r 8
#define _SCRYPT_p 1

#define jane_scrypt(p, pl, s, ss, k, ks) \
    scrypt(p, pl, s, ss, 17, 3, 0, k, ks)

static SHA256_CTX sha256_ctx;

int brainwalletio(unsigned char *pass, size_t pass_sz,
                  unsigned char *salt, size_t salt_sz,
                  unsigned char *out) {
    unsigned char seed1[32], seed2[65];

    int seed1_sz = sizeof(seed1), seed2_sz = (sizeof(seed2) - 1);

    jane_scrypt(pass, pass_sz, salt, salt_sz, seed1, seed1_sz);
    hex(seed1, seed1_sz, seed2, seed2_sz);
    SHA256_Init(&sha256_ctx);
    SHA256_Update(&sha256_ctx, seed2, seed2_sz);
    SHA256_Final(out, &sha256_ctx);

    return 0;
}
