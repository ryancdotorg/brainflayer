/* Copyright (c) 2015 Ryan Castellucci, All Rights Reserved */
#include <stdlib.h>
#include <stdio.h>

#include "hex.h"

int main(int argc, char **argv) {
  char *line = NULL;
  size_t line_sz = 0, buf_sz = 2;
  ssize_t line_read;
  unsigned char *buf = malloc(buf_sz);

  if (argc > 1) {
    fprintf(stderr, "Usage: %s\n", argv[0]);
    return 1;
  }

  // don't flush on newlines)
  setvbuf(stdout, NULL, _IOFBF, 65536);

  while ((line_read = getline(&line, &line_sz, stdin)) > 0) {
    while (line_sz * 2 > buf_sz) {
      buf_sz *= 2;
      buf = realloc(buf, buf_sz);
    }
    if (buf == NULL) {
      fprintf(stderr, "memory error\n");
      return 1;
    }
    --line_read;
    hex(line, line_read, buf, buf_sz);
    if (line_read < 0x4c) {
      printf("%02zx%s\n", line_read, buf);
      printf("%02zx%s87\n", line_read, buf);
    }
    if (line_read < 256) {
      printf("4c%02zx%s\n", line_read, buf);
      printf("4c%02zx%s87\n", line_read, buf);
    }
    if (line_read < 65536) {
      printf("4d%04zx%s\n", line_read, buf);
      printf("4d%04zx%s87\n", line_read, buf);
    }
    if (line_read < 0x100000000LL) {
      printf("4e%08zx%s\n", line_read, buf);
      printf("4e%08zx%s87\n", line_read, buf);
    }
  }

  return 0;
}

/*  vim: set ts=2 sw=2 et ai si: */
