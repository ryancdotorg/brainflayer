/*  Copyright (c) 2015 Ryan Castellucci, All Rights Reserved */
#ifndef __BRAINFLAYER_HASH160_H_
#define __BRAINFLAYER_HASH160_H_

#include <openssl/sha.h>
#include <openssl/ripemd.h>

typedef union hash160_u {
  unsigned char uc[RIPEMD160_DIGEST_LENGTH];
  uint32_t      ul[RIPEMD160_DIGEST_LENGTH>>2];
} hash160_t;

/*  vim: set ts=2 sw=2 et ai si: */
#endif /* __BRAINFLAYER_HASH160_H_ */
