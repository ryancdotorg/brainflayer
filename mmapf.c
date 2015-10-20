/* Copyright (c) 2015 Ryan Castellucci, All Rights Reserved */
#define _LARGEFILE_SOURCE
#define _LARGEFILE64_SOURCE

#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "mmapf.h"

static char *errstr[] = {
  "Unknown error",
  "Not a regular file",
  "Incorrect file size",
  ""
};

char * mmapf_strerror(int errnum) {
  if (errnum < MMAPF_EXFIRST) {
    return strerror(errnum);
  } else if (errnum < MMAPF_EXLAST) {
    return errstr[errnum-MMAPF_EXFIRST];
  } else {
    return errstr[0];
  }
}

int munmapf(mmapf_ctx *ctx) {
  // TODO error checking
  if (ctx->fd >= 0) {
    msync(ctx->mem, ctx->file_sz, MS_SYNC);
    fsync(ctx->fd);
    close(ctx->fd);
  }
  if (ctx->mem != NULL) {
    munmap(ctx->mem, ctx->mmap_sz);
  }
  ctx->file_sz = 0;
  ctx->mmap_sz = 0;
  ctx->mem = NULL;
  ctx->fd = -1;
  return 0;
}

int mmapf(mmapf_ctx *ctx, const unsigned char *filename, size_t size, int flags) {
  size_t page_sz = sysconf(_SC_PAGESIZE);
  struct stat sb;

  int mmode = 0, mflags = 0, madv = 0;
  int fmode = 0, fadv = 0;
  int ret, fd;

  // initialize
  ctx->mem = NULL;
  ctx->fd = -1;
  ctx->file_sz = size;

  // round up to the next multiple of the page size
  ctx->mmap_sz = size % page_sz ? (size/page_sz+1)*page_sz : size;

  mflags |= flags & MMAPF_COW ? MAP_PRIVATE : MAP_SHARED;

  if (flags & MMAPF_RW) {
    mmode |= PROT_READ|PROT_WRITE;
    fmode |= O_RDWR;
  } else if (flags & MMAPF_RD) {
    mflags |= MAP_NORESERVE;
    mmode |= PROT_READ;
    fmode |= O_RDONLY;
  } else if (flags & MMAPF_WR) {
    mmode |= PROT_WRITE;
    fmode |= O_WRONLY;
  }

  if (flags & MMAPF_CR) { fmode |= O_CREAT; }
  if (flags & MMAPF_EX) { fmode |= O_EXCL; }
  if (flags & MMAPF_PRE) { mflags |= MAP_POPULATE; }
  if (flags & MMAPF_NOREUSE) { fadv |= POSIX_FADV_NOREUSE; }
  if (flags & MMAPF_RND) { fadv |= POSIX_FADV_RANDOM; madv |= POSIX_MADV_RANDOM; }
  if (flags & MMAPF_SEQ) { fadv |= POSIX_FADV_SEQUENTIAL; madv |= POSIX_MADV_SEQUENTIAL; }
  if (flags & MMAPF_DONTNEED) { fadv |= POSIX_FADV_DONTNEED; madv |= POSIX_MADV_DONTNEED; }
  if (flags & MMAPF_WILLNEED) {
    fadv |= POSIX_FADV_WILLNEED;
    // seems to fail on anonymous maps
    if (filename) { madv |= POSIX_MADV_WILLNEED; }
  }

  if (!filename) {
    ctx->mem = mmap(NULL, ctx->mmap_sz, mmode, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
  } else {
    if (stat(filename, &sb) == 0) { // file exists
      if (!S_ISREG(sb.st_mode)) { return MMAPF_ENREG; } // not a regular file
      if (sb.st_size != size) { return MMAPF_ESIZE; } // wrong size
      if ((fd = open64(filename, fmode)) < 0) { return errno; } // open failed
    } else if (flags & MMAPF_CR) { // file missing, but creation requested
      if ((fd = open64(filename, fmode)) < 0) { return errno; } // open failed
      if ((ret = posix_fallocate(fd, 0, size)) != 0) {
        // EBADF is returned on an unsupported filesystem, ignore it
        if (ret != EBADF) { return ret; }
      }
    } else { // file missing, creation *not* requested
      return ENOENT;
    }
    
    //if ((ret = posix_fadvise(fd, 0, size, fadv)) != 0) { return ret; }
    posix_fadvise(fd, 0, size, fadv); // ignore result
    ctx->mem = mmap(NULL, ctx->mmap_sz, mmode, mflags, fd, 0);
  }

  if (ctx->mem == MAP_FAILED) {
    return errno;
  } else if (ctx->mem == NULL) {
    return ENOMEM;
  }

  if ((ret = posix_madvise(ctx->mem, ctx->mmap_sz, madv)) != 0) {
    munmap(ctx->mem, ctx->mmap_sz);
    ctx->mem = NULL;
    return ret;
  }

#ifdef MADV_HUGEPAGE
  // reduce overhead for large mappings
  if (size > (1<<26)) { madvise(ctx->mem, ctx->mmap_sz, MADV_HUGEPAGE); }
#endif
#ifdef MADV_DONTDUMP
  // don't include in a core dump
  madvise(ctx->mem, ctx->mmap_sz, MADV_DONTDUMP);
#endif

  return MMAPF_OKAY;
}
