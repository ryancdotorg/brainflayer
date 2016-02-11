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

#include "brainv2.h"

#define SALT_BITS_PER_THREAD 256
#define SALT_BYTES_PER_THREAD (SALT_BITS_PER_THREAD / 8)
#define THREADS 256
#define KEY_SIZE 128

#define first_scrypt(p, pl, s, ss, k, ks) \
    scrypt(p, pl, s, ss, 13, 0, 6, k, ks)
#define middle_scrypt(p, pl, s, ss, k, ks) \
    scrypt(p, pl, s, ss, 15, 0, 6, k, ks)
#define last_scrypt(p, pl, s, ss, k, ks) \
    scrypt(p, pl, s, ss, 13, 0, 6, k, ks)

int brainv2(unsigned char *pass, size_t pass_sz,
            unsigned char *salt, size_t salt_sz,
            unsigned char *out) {
    unsigned char key1[THREADS*SALT_BYTES_PER_THREAD*2];
    unsigned char key2[THREADS*SALT_BYTES_PER_THREAD];
    unsigned char key3[16];

    int key1_sz = sizeof(key1);
    int key2_sz = sizeof(key2);
    int key3_sz = sizeof(key3);

    int t;

    first_scrypt(pass, pass_sz, salt, salt_sz, key1, key1_sz);
    for (t = 0; t < THREADS; ++t) {
      middle_scrypt(key1+((t*2+0)*SALT_BYTES_PER_THREAD), SALT_BYTES_PER_THREAD,
                    key1+((t*2+1)*SALT_BYTES_PER_THREAD), SALT_BYTES_PER_THREAD,
                    key2+(t*SALT_BYTES_PER_THREAD), SALT_BYTES_PER_THREAD);
    }
    last_scrypt(pass, pass_sz, key2, key2_sz, key3, key3_sz);

    hex(key3, key3_sz, out, 33);

    return 0;
}
