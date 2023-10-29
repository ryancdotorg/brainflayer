/*  Copyright (c) 2015 Ryan Castellucci, All Rights Reserved */
#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <stdio.h>
#include <fcntl.h>
#include <math.h>

#include <sys/stat.h>
#include <sys/types.h>

#include "ec_pubkey_fast.h"

#define MIN_WINDOW (4)
#define MAX_WINDOW (29)

int main(int argc, char **argv) {
  int ret;
  int req_bits, req_buckets;
  int act_bits, act_buckets;

  if (argc != 3) {
    fprintf(stderr, "[!] Usage: %s window_size tablefile.tab\n", argv[0]);
    exit(1);
  }

  req_bits = atoi(argv[1]);

  if (req_bits < MIN_WINDOW) {
    fprintf(stderr, "[!] Requested window_size %d too small, must be >= %d\n", req_bits, MIN_WINDOW);
    exit(1);
  }

  if (req_bits > MAX_WINDOW) {
    fprintf(stderr, "[!] Requested window_size %d too large, must be <= %d\n", req_bits, MAX_WINDOW);
    exit(1);
  }

  // identify wasteful window size
  act_bits = req_bits;
  act_buckets = req_buckets = ceil(256.0/req_bits);
  while (act_buckets == req_buckets) {
    act_bits -= 1;
    act_buckets = ceil(256.0/act_bits);
  }
  act_bits += 1;
  act_buckets = ceil(256.0/act_bits);

  if (act_bits < req_bits) {
    fprintf(stderr, "[*] Requested window_size %d is wasteful, retry with %d\n", req_bits, act_bits);
    exit(1);
  }

  fprintf(stderr, "[*] Computing %d x 2^%d point multiplication matrix...\n", act_buckets, act_bits);

  if ((ret = secp256k1_ec_pubkey_precomp_table_save(act_bits, argv[2])) < 0)
    fprintf(stderr, "[!] Failed to write tablefile '%s'\n", argv[2]);

  return ret;
}

/*  vim: set ts=2 sw=2 et ai si: */
