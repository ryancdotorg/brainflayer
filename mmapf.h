/*  Copyright (c) 2015 Ryan Castellucci, All Rights Reserved */
#ifndef __MMAPF_H_
#define __MMAPF_H_

typedef struct {
  void *mem;
  size_t mmap_sz;
  size_t file_sz;
  int fd;
} mmapf_ctx;

// file flags
#define MMAPF_RD       0x0001
#define MMAPF_WR       0x0002
#define MMAPF_RW       (MMAPF_RD|MMAPF_WR)
#define MMAPF_CR       0x0004
#define MMAPF_EX       0x0008

// advise flags
#define MMAPF_RND      0x0100
#define MMAPF_SEQ      0x0200
#define MMAPF_PRE      0x0400
#define MMAPF_COW      0x0800
#define MMAPF_NOREUSE  0x1000
#define MMAPF_WILLNEED 0x2000
#define MMAPF_DONTNEED 0x4000

// convenience
#define MMAPF_RNDRD (MMAPF_RD|MMAPF_RND|MMAPF_PRE|MMAPF_WILLNEED)
#define MMAPF_RNDUP (MMAPF_RW|MMAPF_RND|MMAPF_PRE|MMAPF_WILLNEED)
#define MMAPF_SEQCR (MMAPF_WR|MMAPF_SEQ|MMAPF_CR|MMAPF_EX|MMAPF_NOREUSE|MMAPF_DONTNEED)

// returns
#define MMAPF_OKAY          0
#define MMAPF_EXFIRST    1000
#define MMAPF_ENREG      1001
#define MMAPF_ESIZE      1002
#define MMAPF_EXLAST     1003

char * mmapf_strerror(int);
int mmapf(mmapf_ctx *, const unsigned char *, size_t, int);
int munmapf(mmapf_ctx *);

/*  vim: set ts=2 sw=2 et ai si: */
#endif /* __MMAPF_H_ */
