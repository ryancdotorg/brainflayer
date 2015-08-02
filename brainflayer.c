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

#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/obj_mac.h>

#include <arpa/inet.h> /* for ntohl/htonl */

#include <sys/time.h>
#include <sys/wait.h>
#include <sys/types.h>

#include <secp256k1.h>

#include "bloom.h"
#include "hash160.h"

static unsigned char hash256[SHA256_DIGEST_LENGTH];
static hash160_t hash160_tmp;
static hash160_t hash160_compr;
static hash160_t hash160_uncmp;
static unsigned char *mem;

static unsigned char *bloom;

static SHA256_CTX    *sha256_ctx;
static RIPEMD160_CTX *ripemd160_ctx;

uint64_t time_1, time_2;
int64_t time_delta;

uint64_t getns() {
  uint64_t ns;
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  ns  = ts.tv_nsec;
  ns += ts.tv_sec * 1000000000ULL;
  return ns;
}

int pass2hash160(unsigned char *pass, size_t pass_sz) {
  /* only initialize stuff once */
  static int bwc_is_init = 0;
  if (!bwc_is_init) {
    /* initialize buffers */
    mem = malloc(4096);

    /* initialize hashs */
    sha256_ctx    = malloc(sizeof(*sha256_ctx));
    ripemd160_ctx = malloc(sizeof(*ripemd160_ctx));

    /* set the flag */
    bwc_is_init = 1;
  }

  unsigned char *pub_chr = mem;
  int pub_chr_sz;

  SHA256_Init(sha256_ctx);
  SHA256_Update(sha256_ctx, pass, pass_sz);
  SHA256_Final(hash256, sha256_ctx);

  secp256k1_ecdsa_pubkey_create(pub_chr, &pub_chr_sz, hash256, 0);

#if 0
  i = 0;
  for (i = 0; i < pub_chr_sz; i++) {
    printf("%02x", pub_chr[i]);
  }
  printf("\n");
#endif

  /* yo dawg, i heard you like hashes... */
  SHA256_Init(sha256_ctx);
  SHA256_Update(sha256_ctx, pub_chr, pub_chr_sz);
  SHA256_Final(hash256, sha256_ctx);

  /* ...so i put a hash in your hash */
  RIPEMD160_Init(ripemd160_ctx);
  RIPEMD160_Update(ripemd160_ctx, hash256, SHA256_DIGEST_LENGTH);
  RIPEMD160_Final(hash160_tmp.uc, ripemd160_ctx);
  memcpy(hash160_uncmp.uc, hash160_tmp.uc, 20);

  /* ugly key compression hack */
  pub_chr[0] = 0x02 | (pub_chr[64] & 0x01);

  /* yo dawg, i heard you like hashes... */
  SHA256_Init(sha256_ctx);
  SHA256_Update(sha256_ctx, pub_chr, 33);
  SHA256_Final(hash256, sha256_ctx);

  /* ...so i put a hash in your hash */
  RIPEMD160_Init(ripemd160_ctx);
  RIPEMD160_Update(ripemd160_ctx, hash256, SHA256_DIGEST_LENGTH);
  RIPEMD160_Final(hash160_tmp.uc, ripemd160_ctx);
  memcpy(hash160_compr.uc, hash160_tmp.uc, 20);

  return 0;
}

int main(int argc, char **argv) {
  char *line = NULL;
  size_t line_sz = 0;

  secp256k1_start();

  /* use line buffered output */
  setvbuf(stdout, NULL, _IOLBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);

  if (argc == 2) {
    if ((bloom = bloom_open(argv[1])) == NULL) {
      fprintf(stderr, "failed to open bloom filter.\n");
      exit(1);
    }
  } else if (argc > 2) {
    fprintf(stderr, "too many arguments\n");
    exit(1);
  }

  while (getline(&line, &line_sz, stdin) > 0) {
    line[strlen(line)-1] = 0;
    pass2hash160(line, strlen(line));
    if (argc == 2) {
      if (bloom_chk_hash160(bloom, hash160_uncmp.ul)) {
        fprintf(stdout, "matched: %08x%08x%08x%08x%08x:u:%s\n",
                ntohl(hash160_uncmp.ul[0]),
                ntohl(hash160_uncmp.ul[1]),
                ntohl(hash160_uncmp.ul[2]),
                ntohl(hash160_uncmp.ul[3]),
                ntohl(hash160_uncmp.ul[4]),
                line);
      }
      if (bloom_chk_hash160(bloom, hash160_compr.ul)) {
        fprintf(stdout, "matched: %08x%08x%08x%08x%08x:c:%s\n",
                ntohl(hash160_compr.ul[0]),
                ntohl(hash160_compr.ul[1]),
                ntohl(hash160_compr.ul[2]),
                ntohl(hash160_compr.ul[3]),
                ntohl(hash160_compr.ul[4]),
                line);
      }
    } else {
      fprintf(stdout, "%08x%08x%08x%08x%08x:u:%s\n",
              ntohl(hash160_uncmp.ul[0]),
              ntohl(hash160_uncmp.ul[1]),
              ntohl(hash160_uncmp.ul[2]),
              ntohl(hash160_uncmp.ul[3]),
              ntohl(hash160_uncmp.ul[4]),
              line);
      fprintf(stdout, "%08x%08x%08x%08x%08x:c:%s\n",
              ntohl(hash160_compr.ul[0]),
              ntohl(hash160_compr.ul[1]),
              ntohl(hash160_compr.ul[2]),
              ntohl(hash160_compr.ul[3]),
              ntohl(hash160_compr.ul[4]),
              line);
    }
  }

  secp256k1_stop();

  return 0;
}

/*  vim: set ts=2 sw=2 et ai si: */
