/* Copyright (c) 2015 Ryan Castellucci, All Rights Reserved */
#include <time.h>
#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>

#include <arpa/inet.h> /* for ntohl/htonl */

#include <sys/time.h>
#include <sys/wait.h>
#include <sys/types.h>

#include "hex.h"
#include "bloom.h"
#include "hash160.h"

int main(int argc, char **argv) {
  hash160_t hash;
  char *line = NULL;
  size_t line_sz = 0;
  unsigned char buf[128];
  unsigned char *bloom, *bloomfile;
  FILE *ifile = stdin, *ofile = stdout;

  if (argc != 2) {
    fprintf(stderr, "Usage: %s BLOOM_FILTER_FILE\n", argv[0]);
    return 1;
  }

  bloomfile = argv[1];

  if ((bloom = bloom_open(bloomfile)) == NULL) {
    fprintf(stderr, "failed to open bloom filter.\n");
    return 1;
  }

  while (getline(&line, &line_sz, ifile) > 0) {
    unhex(line, strlen(line), hash.uc, sizeof(hash.uc)); 
    if (bloom_chk_hash160(bloom, hash.ul)) {
      fprintf(ofile, "%s\n", hex(hash.uc, sizeof(hash.uc), buf, sizeof(buf)));
    }
  }

  return 0;
}

/*  vim: set ts=2 sw=2 et ai si: */
