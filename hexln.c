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

  while ((line_read = getline(&line, &line_sz, stdin)) > 0) {
    while (line_sz * 2 > buf_sz) {
      buf_sz *= 2;
      buf = realloc(buf, buf_sz);
    }
    if (buf == NULL) {
      fprintf(stderr, "memory error\n");
      return 1;
    }
    printf("%s\n", hex(line, line_read - 1, buf, buf_sz));
  }

  return 0;
}

/*  vim: set ts=2 sw=2 et ai si: */
