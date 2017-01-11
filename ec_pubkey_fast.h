/*  Copyright (c) 2015 Nicolas Courtois, Guangyan Song, Ryan Castellucci, All Rights Reserved */
#ifndef __EC_PUBKEY_FAST_H_
#define __EC_PUBKEY_FAST_H_

int secp256k1_ec_pubkey_precomp_table_save(int, unsigned char *);
int secp256k1_ec_pubkey_precomp_table(int, unsigned char *);
int secp256k1_ec_pubkey_create_precomp(unsigned char *, int *, const unsigned char *);
int secp256k1_ec_pubkey_incr_init(unsigned char *, unsigned int);
int secp256k1_ec_pubkey_incr(unsigned char *, int *, unsigned char *);

int secp256k1_scalar_add_b32(void *, void *, void *);

void priv_add_uint8(unsigned char *, unsigned char);
void priv_add_uint32(unsigned char *, unsigned int);

void * secp256k1_ec_priv_to_gej(unsigned char *);
int secp256k1_ec_pubkey_add_gej(unsigned char *, int *, void *);

int secp256k1_ec_pubkey_batch_init(unsigned int);
int secp256k1_ec_pubkey_batch_create(unsigned int, unsigned char (*)[65], unsigned char (*)[32]);
int secp256k1_ec_pubkey_batch_incr(unsigned int, unsigned int, unsigned char (*)[65], unsigned char (*)[32], unsigned char[32]);
#endif//__EC_PUBKEY_FAST_H_
