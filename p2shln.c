/* Copyright (c) 2015 Ryan Castellucci, All Rights Reserved */
#include <stdlib.h>
#include <stdio.h>

#include "sha256/sha256.h"
#include "hex.h"

#define UNHEXED_SZ 262144

static unsigned char unhexed[UNHEXED_SZ];

int main(int argc, char **argv) {
  SHA2_256_CTX ctx;
  char *line = NULL;
  size_t line_sz = 0, buf_sz = 1024, nblk = 1;
  ssize_t line_read, last_read = -1;
  unsigned char *buf = malloc(buf_sz);
  unsigned char sha256[32];
  unsigned char hash160[20];


  if (argc > 1) {
    fprintf(stderr, "Usage: %s\n", argv[0]);
    return 1;
  }

  // don't flush on newlines)
  //setvbuf(stdout, NULL, _IOFBF, 65536);

  SHA2_256_Register();

  while ((line_read = getline(&line, &line_sz, stdin)) > 0) {
    while (line_sz * 2 + 64 > buf_sz) {
      buf_sz *= 2;
      buf = realloc(buf, buf_sz);
    }
    if (buf == NULL) {
      fprintf(stderr, "memory error\n");
      return 1;
    }

    // zero out trailing newline
    if (line[line_read-1] == 10) line[line_read-1] = 0;

    unhex(line, line_read, unhexed, line_read >> 1);
    if (line_read != last_read) {
      nblk = SHA2_256_Pad(unhexed, line_read >> 1);
      last_read = line_read;
    }

    Hash160_Raw(hash160, unhexed, nblk);

    //printf("DEBUG %zu %s\n", nblk, hex(unhexed+ 0, 64, buf, buf_sz));
    //printf("DEBUG %zu %s\n", nblk, hex(unhexed+64, 64, buf, buf_sz));
    printf("%s:%s\n", hex(hash160, sizeof(hash160), buf, buf_sz), line);
  }

  return 0;
}

/*  vim: set ts=2 sw=2 et ai si: */
