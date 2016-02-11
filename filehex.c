/* Copyright (c) 2015 Ryan Castellucci, All Rights Reserved */
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "hex.h"

void filehex(FILE *ifile, const unsigned char *filename) {
  unsigned char hexed[65];
  unsigned char buf[65536];
  size_t offset;
  int r, i, buf_pos, i_max;

  offset = buf_pos = 0;
  while ((r = fread(buf + buf_pos, 1, 256, ifile)) > 0) {
    i_max = r + buf_pos - 31;
    for (i = 0; i < i_max; ++i, ++offset) {
      printf("%s:%s,%zu\n", hex(buf+i, 32, hexed, 65), filename, offset);
    }
    memcpy(buf, buf+i, buf_pos = 31);
  }
}

int main(int argc, char **argv) {
  int i;
  FILE *ifile;

  /*
  if (argc > 1) {
    fprintf(stderr, "Usage: %s\n", argv[0]);
    return 1;
  }*/

  if (argc == 1) {
    filehex(stdin, "STDIN");
  } else {
    for (i = 1; i < argc; ++i) {
      if ((ifile = fopen(argv[i], "r")) != NULL) {
        filehex(ifile, argv[i]);
        fclose(ifile);
      }
    }
  }

  return 0;
}

/*  vim: set ts=2 sw=2 et ai si: */
