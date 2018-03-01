/* Copyright (c) 2015 Ryan Castellucci, All Rights Reserved */
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "hex.h"

int main(int argc, char **argv) {
  int i, ret;
  FILE *ifile;
  unsigned char hexed[65];
  unsigned char buffwd[32];
  unsigned char bufrev[32];

  /*
  if (argc > 1) {
    fprintf(stderr, "Usage: %s\n", argv[0]);
    return 1;
  }*/

  if (argc == 1) {
    return -1;
  } else {
    for (i = 1; i < argc; ++i) {
      if ((ifile = fopen(argv[i], "r")) != NULL) {
        while ((ret = fread(buffwd, 32, 1, ifile)) > 0) {
          for (i = 0; i < 32; ++i) {
            bufrev[31-i] = buffwd[i];
          }
          printf("%s\n", hex(bufrev, 32, hexed, 65));
        }
        fclose(ifile);
      }
    }
  }

  return 0;
}

/*  vim: set ts=2 sw=2 et ai si: */
