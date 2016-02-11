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

#define _PBKDF2_i (1<<16)
#define _SCRYPT_N (1<<18)
#define _SCRYPT_r 8
#define _SCRYPT_p 1

#define openssl_pbkdf2(p, pl, s, ss, k, ks) \
    PKCS5_PBKDF2_HMAC(p, pl, s, ss, _PBKDF2_i, EVP_sha256(), ks, k)

/*
#define libscrypt(p, pl, s, ss, k, ks) \
    libscrypt_scrypt(p, pl, s, ss, _SCRYPT_N, _SCRYPT_r, _SCRYPT_p, k, ks)
*/

#define jane_scrypt(p, pl, s, ss, k, ks) \
    scrypt(p, pl, s, ss, 17, 3, 0, k, ks)

int warpwallet(unsigned char *pass, size_t pass_sz,
               unsigned char *salt, size_t salt_sz,
               unsigned char *out) {
    unsigned char seed1[32], seed2[32];

    int i, seed_sz = 32;

    pass[pass_sz] = salt[salt_sz] = 1;
    //if ((ret = libscrypt(pass, pass_sz+1, salt, salt_sz+1, seed1, seed_sz)) != 0) return ret;
    jane_scrypt(pass, pass_sz+1, salt, salt_sz+1, seed1, seed_sz);

    pass[pass_sz] = salt[salt_sz] = 2;
    openssl_pbkdf2(pass, pass_sz+1, salt, salt_sz+1, seed2, seed_sz);

    // xor the scrypt and pbkdf2 output together
    for (i = 0; i < 32; ++i) { out[i] = seed1[i] ^ seed2[i]; }

    return 0;
}
