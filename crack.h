/*  Copyright (c) 2015 Ryan Castellucci, All Rights Reserved */
#ifndef __BRAINFLAYER_CRACK_H_
#define __BRAINFLAYER_CRACK_H_

#include <openssl/sha.h>
#include <openssl/ripemd.h>

#define PWF_BUF_SZ 1024

typedef union hash160_u {
  unsigned char uc[RIPEMD160_DIGEST_LENGTH];
  uint32_t      ul[RIPEMD160_DIGEST_LENGTH>>2];
} hash160_t;

typedef struct keydata_u {
  int state;
  unsigned char[PWF_BUF_SZ] password;
  unsigned char[SHA256_DIGEST_LENGTH] priv;
  unsigned char[RIPEMD160_DIGEST_LENGTH] uaddr;
  unsigned char[RIPEMD160_DIGEST_LENGTH] caddr;
} keydata_t;

/*  vim: set ts=2 sw=2 et ai si: */
#endif /* __BRAINFLAYER_CRACK_H_ */
