/* Copyright (c) 2020 Ryan Castellucci, All Rights Reserved */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "sha256/sha256.h"
#include "b58/b58.h"
#include "hex.h"

int main() {
  ssize_t r;
  unsigned char h160[40];
  unsigned char hexed[50];
  unsigned char ver = 0;

  char *line = NULL;
  size_t line_sz = 0;
  ssize_t line_read;

  SHA2_256_Register(-1);

  while ((line_read = getline(&line, &line_sz, stdin)) > 0) {
    line[line_read-1] = 0;
    //r = b58d_raw(h160, sizeof(h160), line, line_read-1);//, &ver);
    r = b58d_chk(h160, sizeof(h160), line, line_read-1, &ver);
    if (r >= 0) {
      printf("%s\n", hex(h160, sizeof(h160), hexed, r*2));
    } else {
      fprintf(stderr, "Could not parse '%s' error %zd\n", line, r);
    }
  }

  return 0;
}

/*  vim: set ts=2 sw=2 et ai si: */
