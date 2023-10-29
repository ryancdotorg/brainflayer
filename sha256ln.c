/* Copyright (c) 2015 Ryan Castellucci, All Rights Reserved */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "sha256/sha256.h"
#include "hex.h"

int main(int argc, char **argv) {
  int i;
  char *line = NULL;
  size_t line_sz = 0;
  ssize_t line_read;
  unsigned char hexed[66];
  unsigned char hash[32];
  SHA2_256_CTX ctx;

  SHA2_256_Register(15);

  if (argc > 1) {
    SHA2_256_Init(&ctx);
    for (i = 1; i < argc; ++i) {
      SHA2_256_Update(&ctx, argv[i], strlen(argv[i]));
    }
    SHA2_256_Final(hash, &ctx);
    printf("%s\n", hex(hash, sizeof(hash), hexed, sizeof(hexed)));
    //fprintf(stderr, "Usage: %s\n", argv[0]);
    return 0;
  }

  while ((line_read = getline(&line, &line_sz, stdin)) > 0) {
    SHA2_256_Init(&ctx);
    SHA2_256_Update(&ctx, line, line_read - 1);
    SHA2_256_Final(hash, &ctx);
    printf("%s\n", hex(hash, sizeof(hash), hexed, sizeof(hexed)));
  }

  return 0;
}

/*  vim: set ts=2 sw=2 et ai si: */
