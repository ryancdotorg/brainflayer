/*  Copyright (c) 2015 Ryan Castellucci, All Rights Reserved */
#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <stdio.h>
#include <fcntl.h>

#include <sys/stat.h>
#include <sys/types.h>

#include "ec_pubkey_fast.h"

int main(int argc, char **argv) {
  int ret;
  if (argc != 3) {
    fprintf(stderr, "[!] Usage: %s window_size tablefile.tab\n", argv[0]);
    exit(1);
  }

  if ((ret = secp256k1_ec_pubkey_precomp_table_save(atoi(argv[1]), argv[2])) < 0)
    fprintf(stderr, "[!] Failed to write tablefile '%s'\n", argv[2]);

  return ret;
}

/*  vim: set ts=2 sw=2 et ai si: */
