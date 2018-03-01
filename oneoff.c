/* Copyright (c) 2015 Ryan Castellucci, All Rights Reserved */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "hex.h"

//#include "secp256k1/src/libsecp256k1-config.h"
#include "secp256k1/include/secp256k1.h"

//#include "secp256k1/src/util.h"
//#include "secp256k1/src/num_impl.h"
//#include "secp256k1/src/field_impl.h"
//#include "secp256k1/src/field_10x26_impl.h"
//#include "secp256k1/src/scalar_impl.h"
//#include "secp256k1/src/group_impl.h"

#include "ec_pubkey_fast.h"

int main(int argc, char **argv) {
  char *line = NULL;
  size_t line_sz = 0, buf_sz = 2;
  ssize_t line_read;
  unsigned char *buf = malloc(buf_sz);

  int pub_chr_sz;

  unsigned char addpriv[32];
  unsigned char output[256];
  unsigned char pub_chr[65];
  unsigned char sign;

  //secp256k1_pubkey_t pubkey;
  secp256k1_context_t *ctx;
  void *addgej;

  if (argc > 1) {
    fprintf(stderr, "Usage: %s\n", argv[0]);
    return 1;
  }

  ctx = secp256k1_context_create(3);
  secp256k1_ec_pubkey_precomp_table(10, NULL);

  memset(&addpriv, 0, 32);
  addpriv[31] = 1;
  addgej = secp256k1_ec_priv_to_gej(addpriv);
  //printf("%s\n", hex(addgej, 128, output, 256));


  while ((line_read = getline(&line, &line_sz, stdin)) > 0) {
    while (line_sz * 2 > buf_sz) {
      buf_sz *= 2;
      buf = realloc(buf, buf_sz);
    }
    if (buf == NULL) {
      fprintf(stderr, "memory error\n");
      return 1;
    }
    
    line[64] = 0;
    for (sign = 0x02; sign <= 0x03; ++sign) {
      unhex(line, 64, pub_chr + 1, 32);
      pub_chr[0] = sign;
      pub_chr_sz = 33;
      secp256k1_ec_pubkey_add_gej(pub_chr, &pub_chr_sz, addgej);
      hex(pub_chr, 65, output, 256);
      output[66] = 0;
      printf("%s:%s\n", line, output + 2);
    }
  }

  return 0;
}

/*  vim: set ts=2 sw=2 et ai si: */
