/* Copyright (c) 2015 Ryan Castellucci, All Rights Reserved */
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "bloom.h"
#include "mmapf.h"

void bloom_set_hash160(unsigned char *bloom, uint32_t *h) {
  unsigned int t;
  t = BH00(h); BLOOM_SET_BIT(t);
  t = BH01(h); BLOOM_SET_BIT(t);
  t = BH02(h); BLOOM_SET_BIT(t);
  t = BH03(h); BLOOM_SET_BIT(t);
  t = BH04(h); BLOOM_SET_BIT(t);
  t = BH05(h); BLOOM_SET_BIT(t);
  t = BH06(h); BLOOM_SET_BIT(t);
  t = BH07(h); BLOOM_SET_BIT(t);
  t = BH08(h); BLOOM_SET_BIT(t);
  t = BH09(h); BLOOM_SET_BIT(t);
  t = BH10(h); BLOOM_SET_BIT(t);
  t = BH11(h); BLOOM_SET_BIT(t);
  t = BH12(h); BLOOM_SET_BIT(t);
  t = BH13(h); BLOOM_SET_BIT(t);
  t = BH14(h); BLOOM_SET_BIT(t);
  t = BH15(h); BLOOM_SET_BIT(t);
  t = BH16(h); BLOOM_SET_BIT(t);
  t = BH17(h); BLOOM_SET_BIT(t);
  t = BH18(h); BLOOM_SET_BIT(t);
  t = BH19(h); BLOOM_SET_BIT(t);
}

/*
int bloom_save(unsigned char *filename, unsigned char *bloom);
*/

/*  vim: set ts=2 sw=2 et ai si: */
