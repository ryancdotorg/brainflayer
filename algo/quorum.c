/* Copyright (c) 2017 Ryan Castellucci, All Rights Reserved */
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

#define _PBKDF2_i 2000

#define openssl_pbkdf2(p, pl, s, ss, k, ks) \
    PKCS5_PBKDF2_HMAC(p, pl, s, ss, _PBKDF2_i, EVP_sha256(), ks, k)

int quorum(unsigned char *pass, size_t pass_sz,
           unsigned char *salt, size_t salt_sz,
           unsigned char *out) {
    unsigned char seed[4096];
    int seed_sz = pass_sz + salt_sz;

    memcpy(seed, pass, pass_sz);
    memcpy(seed+pass_sz, salt, salt_sz);

    openssl_pbkdf2(seed, seed_sz, seed, seed_sz, out, 32);

    return 0;
}
