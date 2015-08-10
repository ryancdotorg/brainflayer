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

int _bloom_mmap(unsigned char **bloom, unsigned char *filename) {
  int ret, fd, i;
  struct stat sb;
  unsigned char z[1024*1024];

  if (stat(filename, &sb) == 0) {
    if (!S_ISREG(sb.st_mode) || sb.st_size != BLOOM_SIZE)
      return -100;
    if ((fd = open(filename, O_RDWR)) < 0)
      return fd;
  } else {
    /*  Assume the file didn't exist */
    if ((fd = open(filename, O_RDWR | O_CREAT | O_EXCL, 0660)) < 0)
      return fd;
    /* Make sure the buffer is zeroed */
    memset(z, 0, sizeof(z));
    i = BLOOM_SIZE;
    /* pre-write an empty bloom filter */
    while (i > 0) {
      if (i > sizeof(z)) {
        ret = write(fd, z, sizeof(z));
      } else {
        ret = write(fd, z, i);
      }
      //fprintf(stderr, "bloom init write %2d %9d %9d\n", fd, ret, i);
      /* We shouldn't be getting short writes */
      if (ret != sizeof(z))
        return -101;
      i -= ret;
    }
  }

  if ((ret = posix_fadvise(fd, 0, BLOOM_SIZE, POSIX_FADV_WILLNEED|POSIX_FADV_RANDOM)) < 0)
    return ret;

  /* We should now have a file of the right size open. */
  *bloom = mmap(NULL, BLOOM_SIZE, PROT_READ, MAP_SHARED|MAP_NORESERVE|MAP_POPULATE, fd, 0);
  return fd;
}

unsigned char * bloom_open(unsigned char *filename) {
  int fd;
  unsigned char *bloom;
  bloom = malloc(sizeof(void *));

  if ((fd = _bloom_mmap(&bloom, filename) < 0))
    return NULL;
  return bloom;
}

/*
int bloom_save(unsigned char *filename, unsigned char *bloom);
*/

/*  vim: set ts=2 sw=2 et ai si: */
