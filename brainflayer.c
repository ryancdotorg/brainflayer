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

#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/obj_mac.h>

#include <arpa/inet.h> /* for ntohl/htonl */

#include <sys/time.h>
#include <sys/wait.h>
#include <sys/types.h>

#include "secp256k1/include/secp256k1.h"

#include "hex.h"
#include "bloom.h"
#include "hash160.h"

#include "warpwallet.h"
#include "brainwalletio.h"

static int brainflayer_is_init = 0;

static unsigned char hash256[SHA256_DIGEST_LENGTH];
static hash160_t hash160_tmp;
static hash160_t hash160_compr;
static hash160_t hash160_uncmp;
static unsigned char *mem;

static unsigned char *bloom = NULL;

static unsigned char unhexed[4096];

static SHA256_CTX    *sha256_ctx;
static RIPEMD160_CTX *ripemd160_ctx;

#define bail(code, ...) \
do { \
  fprintf(stderr, __VA_ARGS__); \
  exit(code); \
} while (0)

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

inline static int priv2hash160(unsigned char *priv) {
  /* only initialize stuff once */
  if (!brainflayer_is_init) {
    /* initialize buffers */
    mem = malloc(4096);

    /* initialize hashs */
    sha256_ctx    = malloc(sizeof(*sha256_ctx));
    ripemd160_ctx = malloc(sizeof(*ripemd160_ctx));

    /* set the flag */
    brainflayer_is_init = 1;
  }

  unsigned char *pub_chr = mem;
  int pub_chr_sz;

  secp256k1_ecdsa_pubkey_create(pub_chr, &pub_chr_sz, priv, 0);

#if 0
  i = 0;
  for (i = 0; i < pub_chr_sz; i++) {
    printf("%02x", pub_chr[i]);
  }
  printf("\n");
#endif

  /* compute hash160 for uncompressed public key */
  /* sha256(pub) */
  SHA256_Init(sha256_ctx);
  SHA256_Update(sha256_ctx, pub_chr, pub_chr_sz);
  SHA256_Final(hash256, sha256_ctx);
  /* ripemd160(sha256(pub)) */
  RIPEMD160_Init(ripemd160_ctx);
  RIPEMD160_Update(ripemd160_ctx, hash256, SHA256_DIGEST_LENGTH);
  RIPEMD160_Final(hash160_tmp.uc, ripemd160_ctx);

  /* save result to global struct */
  memcpy(hash160_uncmp.uc, hash160_tmp.uc, 20);

  /* quick and dirty public key compression */
  pub_chr[0] = 0x02 | (pub_chr[64] & 0x01);

  /* compute hash160 for compressed public key */
  /* sha256(pub) */
  SHA256_Init(sha256_ctx);
  SHA256_Update(sha256_ctx, pub_chr, 33);
  SHA256_Final(hash256, sha256_ctx);
  /* ripemd160(sha256(pub)) */
  RIPEMD160_Init(ripemd160_ctx);
  RIPEMD160_Update(ripemd160_ctx, hash256, SHA256_DIGEST_LENGTH);
  RIPEMD160_Final(hash160_tmp.uc, ripemd160_ctx);

  /* save result to global struct */
  memcpy(hash160_compr.uc, hash160_tmp.uc, 20);

  return 0;
}

static int pass2hash160(unsigned char *pass, size_t pass_sz) {
  /* only initialize stuff once */
  if (!brainflayer_is_init) {
    /* initialize buffers */
    mem = malloc(4096);

    /* initialize hashs */
    sha256_ctx    = malloc(sizeof(*sha256_ctx));
    ripemd160_ctx = malloc(sizeof(*ripemd160_ctx));

    /* set the flag */
    brainflayer_is_init = 1;
  }

  /* privkey = sha256(passphrase) */
  SHA256_Init(sha256_ctx);
  SHA256_Update(sha256_ctx, pass, pass_sz);
  SHA256_Final(hash256, sha256_ctx);

  return priv2hash160(hash256);
}

static int hexpass2hash160(unsigned char *hpass, size_t hpass_sz) {
  return pass2hash160(unhex(hpass, hpass_sz, unhexed, sizeof(unhexed)), hpass_sz>>1);
}

static int hexpriv2hash160(unsigned char *hpriv, size_t hpriv_sz) {
  return priv2hash160(unhex(hpriv, hpriv_sz, unhexed, sizeof(unhexed)));
}

static unsigned char *kdfsalt;
static size_t kdfsalt_sz;

static int warppass2hash160(unsigned char *pass, size_t pass_sz) {
  int ret;
  if ((ret = warpwallet(pass, pass_sz, kdfsalt, kdfsalt_sz, hash256)) != 0) return ret;
  pass[pass_sz] = 0;
  return priv2hash160(hash256);
}

static int bwiopass2hash160(unsigned char *pass, size_t pass_sz) {
  int ret;
  if ((ret = brainwalletio(pass, pass_sz, kdfsalt, kdfsalt_sz, hash256)) != 0) return ret;
  pass[pass_sz] = 0;
  return priv2hash160(hash256);
}

static unsigned char *kdfpass;
static size_t kdfpass_sz;

static int warpsalt2hash160(unsigned char *salt, size_t salt_sz) {
  int ret;
  if ((ret = warpwallet(kdfpass, kdfpass_sz, salt, salt_sz, hash256)) != 0) return ret;
  salt[salt_sz] = 0;
  return priv2hash160(hash256);
}

static int bwiosalt2hash160(unsigned char *salt, size_t salt_sz) {
  int ret;
  if ((ret = brainwalletio(kdfpass, kdfpass_sz, salt, salt_sz, hash256)) != 0) return ret;
  salt[salt_sz] = 0;
  return priv2hash160(hash256);
}

// function pointer
static int (*input2hash160)(unsigned char *, size_t);

inline static void fprintresult(FILE *f, hash160_t *hash,
                                unsigned char compressed,
                                unsigned char *type,
                                unsigned char *input) {
  fprintf(f, "%08x%08x%08x%08x%08x:%c:%s:%s\n",
          ntohl(hash->ul[0]),
          ntohl(hash->ul[1]),
          ntohl(hash->ul[2]),
          ntohl(hash->ul[3]),
          ntohl(hash->ul[4]),
          compressed,
          type,
          input);
}


void usage(unsigned char *name) {
  printf("Usage: %s [OPTION]...\n\n\
 -a                          open output file in append mode\n\
 -b FILE                     check for matches against bloom filter FILE\n\
 -i FILE                     read from FILE instead of stdin\n\
 -o FILE                     write to FILE instead of stdout\n\
 -t TYPE                     inputs are TYPE - supported types:\n\
                             str (default) - classic brainwallet passphrases\n\
                             hex - classic brainwallets (hex encoded)\n\
                             priv - hex encoded private keys\n\
                             warp - WarpWallet (supports -s or -p)\n\
 -s SALT                     use SALT for salted input types (default: none)\n\
 -p PASSPHRASE               use PASSPHRASE for salted input types, inputs\n\
                             will be treated as salts\n\
 -h                          show this help\n", name);
//q, --quiet                 suppress non-error messages
  exit(1);
}

int main(int argc, char **argv) {
  FILE *ifile = stdin;
  FILE *ofile = stdout;

  char *line = NULL;
  size_t line_sz = 0;

  int c, spok = 0, aopt = 0;
  unsigned char *bopt = NULL, *iopt = NULL, *oopt = NULL;
  unsigned char *topt = NULL, *sopt = NULL, *popt = NULL;

  while ((c = getopt(argc, argv, "ab:hi:o:p:s:t:")) != -1) {
    switch (c) {
      case 'a':
        aopt = 1; // open output file in append mode
        break;
      case 'b':
        bopt = optarg; // bloom filter file
        break;
      case 'i':
        iopt = optarg; // input file
        break;
      case 'o':
        oopt = optarg; // output file
        break;
      case 's':
        sopt = optarg; // salt
        break;
      case 'p':
        popt = optarg; // passphrase
        break;
      case 't':
        topt = optarg; // type of input
        break;
      case 'h':
        // show help
        usage(argv[0]);
        return 0;
      case '?':
        // show error
        return 1;
      default:
        // should never be reached...
        printf("got option '%c' (%d)\n", c, c);
        return 1;
    }
  }

  if (optind < argc) {
    if (optind == 1 && argc == 2) {
      // older versions of brainflayer had the bloom filter file as a
      // single optional argument, this keeps compatibility with that
      bopt = argv[1];
    } else {
      fprintf(stderr, "Invalid arguments:\n");
      while (optind < argc) {
        fprintf(stderr, "    '%s'\n", argv[optind++]);
      }
      exit(1);
    }
  }

  if (topt != NULL) {
    if (strcmp(topt, "str") == 0) {
      input2hash160 = &pass2hash160;
    } else if (strcmp(topt, "hex") == 0) {
      input2hash160 = &hexpass2hash160;
    } else if (strcmp(topt, "priv") == 0) {
      input2hash160 = &hexpriv2hash160;
    } else if (strcmp(topt, "warp") == 0) {
      spok = 1;
      input2hash160 = popt ? &warpsalt2hash160 : &warppass2hash160;
    } else if (strcmp(topt, "bwio") == 0) {
      spok = 1;
      input2hash160 = popt ? &bwiosalt2hash160 : &bwiopass2hash160;
    } else {
      bail(1, "Unknown input type '%s'.\n", topt);
    }
  } else {
    topt = "str";
    input2hash160 = &pass2hash160;
  }

  if (spok) {
    if (sopt && popt) {
      bail(1, "Cannot specify both a salt and a passphrase\n");
    }
    if (popt) {
      kdfpass = popt;
      kdfpass_sz = strlen(popt);
    } else {
      if (sopt) {
        kdfsalt = sopt;
        kdfsalt_sz = strlen(kdfsalt);
      } else {
        kdfsalt = malloc(0);
        kdfsalt_sz = 0;
      }
    }
  } else {
    if (popt) {
      bail(1, "Specifying a passphrase not supported with input type '%s'\n", topt);
    } else if (sopt) {
      bail(1, "Specifying a salt not supported with this input type '%s'\n", topt);
    }
  }

  if (bopt) {
    if ((bloom = bloom_open(bopt)) == NULL) {
      bail(1, "failed to open bloom filter.\n");
    }
  }

  if (iopt) {
    if ((ifile = fopen(iopt, "r")) == NULL) {
      bail(1, "failed to open '%s' for reading: %s\n", iopt, strerror(errno));
    }
  }

  if (oopt) {
    if ((ofile = fopen(oopt, (aopt ? "a" : "w"))) == NULL) {
      bail(1, "failed to open '%s' for writing: %s\n", oopt, strerror(errno));
    }
  }

  /* use line buffered output */
  setvbuf(ofile,  NULL, _IOLBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);

  secp256k1_start();

  while (getline(&line, &line_sz, ifile) > 0) {
    line[strlen(line)-1] = 0;
    input2hash160(line, strlen(line));
    if (bloom) {
      if (bloom_chk_hash160(bloom, hash160_uncmp.ul)) {
        fprintresult(ofile, &hash160_uncmp, 'u', topt, line);
      }
      if (bloom_chk_hash160(bloom, hash160_compr.ul)) {
        fprintresult(ofile, &hash160_compr, 'c', topt, line);
      }
    } else {
      fprintresult(ofile, &hash160_uncmp, 'u', topt, line);
      fprintresult(ofile, &hash160_compr, 'c', topt, line);
    }
  }

  secp256k1_stop();

  return 0;
}

/*  vim: set ts=2 sw=2 et ai si: */
