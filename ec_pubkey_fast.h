/*  Copyright (c) 2015 Nicolas Courtois, Guangyan Song, Ryan Castellucci, All Rights Reserved */
#ifndef __EC_PUBKEY_FAST_H_
#define __EC_PUBKEY_FAST_H_

int secp256k1_ec_pubkey_precomp_table_save(int, unsigned char *);
int secp256k1_ec_pubkey_precomp_table(int, unsigned char *);
int secp256k1_ec_pubkey_create_precomp(unsigned char *, int *, const unsigned char *);
int secp256k1_ec_pubkey_incr_init(unsigned char *, unsigned char);
int secp256k1_ec_pubkey_incr(unsigned char *, int *, unsigned char *);

void priv_add_uint8(unsigned char *, unsigned char);

#endif//__EC_PUBKEY_FAST_H_
