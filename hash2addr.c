/* Copyright (c) 2015 Ryan Castellucci, All Rights Reserved */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "sha256/sha256.h"
#include "b58/b58.h"

int main() {
  size_t r;
  unsigned char addr[40];
  unsigned char h160[20];

  SHA2_256_Register(-1);

  while ((r = fread(h160, 20, 1, stdin)) == 1) {
    b58e_chk(addr, 40, h160, 20, 0);
    printf("%s\n", addr);
  }

  return 0;
}

/*  vim: set ts=2 sw=2 et ai si: */
