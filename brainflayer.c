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

#include <sys/time.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/sysinfo.h>

#include "sha256/sha256.h"

#include "ec_pubkey_fast.h"

#include "hex.h"
#include "bloom.h"
#include "mmapf.h"
#include "hash160.h"
#include "hsearchf.h"

#include "algo/quorum.h"
#include "algo/brainv2.h"
#include "algo/warpwallet.h"
#include "algo/brainwalletio.h"
#include "algo/sha3.h"

#include "b58/b58.h"

// raise this if you really want, but quickly diminishing returns
#define BATCH_MAX 4096

//static int brainflayer_is_init = 1;

typedef struct pubhashfn_s {
   void (*fn)(hash160_t *, const unsigned char *);
   char id;
} pubhashfn_t;

static unsigned char keystream[BATCH_MAX+32];

#ifndef SHOW_DUPLICATE_HITS
static unsigned char *hits;
static int hits_max = 65536;
#endif//SHOW_DUPLICATE_HITS

static unsigned char *mem;

static mmapf_ctx bloom_mmapf;
static unsigned char *bloom = NULL;

static unsigned char *unhexed = NULL;
static size_t unhexed_sz = 4096;

#define bail(code, ...) \
do { \
  fprintf(stderr, __VA_ARGS__); \
  exit(code); \
} while (0)

#define chkmalloc(S) _chkmalloc(S, __FILE__, __LINE__)
static void * _chkmalloc(size_t size, unsigned char *file, unsigned int line) {
  void *ptr = malloc(size);
  if (ptr == NULL) {
    bail(1, "malloc(%zu) failed at %s:%u: %s\n", size, file, line, strerror(errno));
  }
  return ptr;
}

#define chkrealloc(P, S) _chkrealloc(P, S, __FILE__, __LINE__);
static void * _chkrealloc(void *ptr, size_t size, unsigned char *file, unsigned int line) {
  void *ptr2 = realloc(ptr, size);
  if (ptr2 == NULL) {
    bail(1, "realloc(%p, %zu) failed at %s:%u: %s\n", ptr, size, file, line, strerror(errno));
  }
  return ptr2;
}

uint64_t getns() {
  uint64_t ns;
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  ns  = ts.tv_nsec;
  ns += ts.tv_sec * 1000000000ULL;
  return ns;
}

/*
static inline void brainflayer_init_globals() {
  // only initialize stuff once
  if (!brainflayer_is_init) {
    SHA2_256_Register(-1);
    // initialize buffers
    mem = chkmalloc(4096);
#ifndef SHOW_DUPLICATE_HITS
    hits = chkmalloc(20 * hits_max);
#endif//SHOW_DUPLICATE_HITS
    unhexed = chkmalloc(unhexed_sz);

    // set the flag
    brainflayer_is_init = 1;
  }
}
//*/

// function pointers
static int (*input2priv)(unsigned char *, unsigned char *, size_t);

static inline unsigned char compress(unsigned char *upub) {
  unsigned char hdr = upub[0];
  upub[0] = 0x02 | (upub[64] & 0x01); // quick and dirty public key compression
  return hdr;
}

/* bitcoin uncompressed address */
static void uhash160(hash160_t *h, const unsigned char *upub) {
  Hash160_65(h->uc, upub);
}

/* bitcoin compressed address */
static void chash160(hash160_t *h, const unsigned char *upub) {
  unsigned char *cpub = (unsigned char *)upub;
  unsigned char hdr = compress(cpub);

  //hdr = upub[0]; // save public key header byte
  //cpub[0] = 0x02 | (upub[64] & 0x01); // quick and dirty public key compression
  Hash160_33(h->uc, cpub);
  cpub[0] = hdr; // restore public key header byte
}

#define OP_0             0x00
#define OP_1             0x51
#define OP_DUP           0x76
#define OP_HASH160       0xa9
#define OP_EQUALVERIFY   0x88
#define OP_CHECKSIG      0xac
#define OP_CHECKMULTISIG 0xae

// P2SH-P2WPKH
static void whash160(hash160_t *h, const unsigned char *upub) {
  static unsigned char spk[] = {
    OP_0, 20,
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0
  };
  unsigned char *cpub = (unsigned char *)upub;
  unsigned char hdr = compress(cpub);
  Hash160_33(spk+2, cpub);
  cpub[0] = hdr; // restore public key header byte
  Hash160_22(h->uc, spk);
}

// P2SH-P2WPKH, but must run immediately after compressed P2PKH
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
static void whash160_pre(hash160_t *h, const unsigned char *upub) {
  static unsigned char spk[] = {
    OP_0, 20,
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0
  };
  memcpy(spk+2, h, 20);
  Hash160_22(h->uc, spk);
}
#pragma GCC diagnostic pop

// P2SH-P2PKH uncompressed
static void Hhash160(hash160_t *h, const unsigned char *upub) {
  static unsigned char spk[] = {
    OP_DUP, OP_HASH160, 20,
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    OP_EQUALVERIFY, OP_CHECKSIG
  };
  Hash160_65(spk+3, upub);
  Hash160_25(h->uc, spk);
}

// P2SH-P2PKH compressed
static void hhash160(hash160_t *h, const unsigned char *upub) {
  static unsigned char spk[] = {
    OP_DUP, OP_HASH160, 20,
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    OP_EQUALVERIFY, OP_CHECKSIG
  };
  unsigned char *cpub = (unsigned char *)upub;
  unsigned char hdr = compress(cpub);
  Hash160_33(spk+3, cpub);
  cpub[0] = hdr; // restore public key header byte
  Hash160_25(h->uc, spk);
}

// P2SH-P2PK uncompresssed
static void Phash160(hash160_t *h, const unsigned char *upub) {
  static unsigned char spk[] = {
    65,
    0,
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    OP_CHECKSIG
  };
  memcpy(spk+1, upub, 65);
  Hash160_67(h->uc, spk);
}

// P2SH-P2PK compresssed
static void phash160(hash160_t *h, const unsigned char *upub) {
  static unsigned char spk[] = {
    33,
    0,
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    OP_CHECKSIG
  };
  memcpy(spk+1, upub, 33);
  spk[1] = 0x02 | (upub[64] & 0x01);
  Hash160_35(h->uc, spk);
}

// P2SH 1-of-1 multisig uncompressed
static void Mhash160(hash160_t *h, const unsigned char *upub) {
  static unsigned char spk[] = {
    OP_1, 65,
    0,
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    OP_1, OP_CHECKMULTISIG
  };
  memcpy(spk+2, upub, 65);
  Hash160_69(h->uc, spk);
}

// P2SH 1-of-1 multisig compressed
static void mhash160(hash160_t *h, const unsigned char *upub) {
  static unsigned char spk[] = {
    OP_1, 33,
    0,
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    OP_1, OP_CHECKMULTISIG
  };
  memcpy(spk+2, upub, 33);
  spk[2] = 0x02 | (upub[64] & 0x01);
  Hash160_37(h->uc, spk);
}

/* ethereum address */
static void ehash160(hash160_t *h, const unsigned char *upub) {
  SHA3_256_CTX ctx;
  unsigned char hash[SHA256_DIGEST_LENGTH];

  /* compute hash160 for uncompressed public key */
  /* keccak_256_last160(pub) */
  KECCAK_256_Init(&ctx);
  KECCAK_256_Update(&ctx, upub+1, 64);
  KECCAK_256_Final(hash, &ctx);
  memcpy(h->uc, hash+12, 20);
}

/* msb of x coordinate of public key */
static void xhash160(hash160_t *h, const unsigned char *upub) {
  memcpy(h->uc, upub+1, 20);
}

/* msb of entire public key */
static void shash160(hash160_t *h, const unsigned char *upub) {
  memcpy(h->uc, upub, 20);
}

static int pass2priv(unsigned char *priv, unsigned char *pass, size_t pass_sz) {
  SHA2_256(priv, pass, pass_sz);

  return 0;
}

static int keccak2priv(unsigned char *priv, unsigned char *pass, size_t pass_sz) {
  SHA3_256_CTX ctx;

  KECCAK_256_Init(&ctx);
  KECCAK_256_Update(&ctx, pass, pass_sz);
  KECCAK_256_Final(priv, &ctx);

  return 0;
}

/* ether.camp "2031 passes of SHA-3 (Keccak)" */
static int camp2priv(unsigned char *priv, unsigned char *pass, size_t pass_sz) {
  SHA3_256_CTX ctx;
  int i;

  KECCAK_256_Init(&ctx);
  KECCAK_256_Update(&ctx, pass, pass_sz);
  KECCAK_256_Final(priv, &ctx);

  for (i = 1; i < 2031; ++i) {
    KECCAK_256_Init(&ctx);
    KECCAK_256_Update(&ctx, priv, 32);
    KECCAK_256_Final(priv, &ctx);
  }

  return 0;
}

static int sha32priv(unsigned char *priv, unsigned char *pass, size_t pass_sz) {
  SHA3_256_CTX ctx;

  SHA3_256_Init(&ctx);
  SHA3_256_Update(&ctx, pass, pass_sz);
  SHA3_256_Final(priv, &ctx);

  return 0;
}

/* Parity Wallet https://archive.is/O1RBi https://web.archive.org/web/20170507173411/https://github.com/ethereum/wiki/wiki/Brain-Wallet */
static int parity2priv(unsigned char *priv, unsigned char *pass, size_t pass_sz) {
  unsigned char hash[32];
  unsigned char epub[65];

  SHA3_256_CTX ctx;
  int i, sz;

  KECCAK_256_Init(&ctx);
  KECCAK_256_Update(&ctx, pass, pass_sz);
  KECCAK_256_Final(priv, &ctx);

  for (i = 0; i < 16384; ++i) {
    KECCAK_256_Init(&ctx);
    KECCAK_256_Update(&ctx, priv, 32);
    KECCAK_256_Final(priv, &ctx);
  }

  do {
    KECCAK_256_Init(&ctx);
    KECCAK_256_Update(&ctx, priv, 32);
    KECCAK_256_Final(priv, &ctx);

    // XXX Parity Wallet verifies that the private key is well formed here, but
    // we don't bother because anything smaller than the following is fine
    // fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

    secp256k1_ec_pubkey_create_precomp(epub, &sz, priv);

    KECCAK_256_Init(&ctx);
    KECCAK_256_Update(&ctx, epub+1, 64);
    KECCAK_256_Final(hash, &ctx);
  } while (hash[12] != 0);

  return 0;
}

static int rawpriv2priv(unsigned char *priv, unsigned char *rawpriv, size_t rawpriv_sz) {
  memcpy(priv, rawpriv, rawpriv_sz);
  return 0;
}

static unsigned char *kdfsalt;
static size_t kdfsalt_sz;

static int warppass2priv(unsigned char *priv, unsigned char *pass, size_t pass_sz) {
  int ret;
  if ((ret = warpwallet(pass, pass_sz, kdfsalt, kdfsalt_sz, priv)) != 0) return ret;
  pass[pass_sz] = 0;
  return 0;
}

static int bwiopass2priv(unsigned char *priv, unsigned char *pass, size_t pass_sz) {
  int ret;
  if ((ret = brainwalletio(pass, pass_sz, kdfsalt, kdfsalt_sz, priv)) != 0) return ret;
  pass[pass_sz] = 0;
  return 0;
}

static int brainv2pass2priv(unsigned char *priv, unsigned char *pass, size_t pass_sz) {
  unsigned char hexout[33];
  int ret;
  if ((ret = brainv2(pass, pass_sz, kdfsalt, kdfsalt_sz, hexout)) != 0) return ret;
  pass[pass_sz] = 0;
  return pass2priv(priv, hexout, sizeof(hexout)-1);
}

static int quorumpass2priv(unsigned char *priv, unsigned char *pass, size_t pass_sz) {
  return quorum(pass, pass_sz, kdfsalt, kdfsalt_sz, priv);
}

static unsigned char *kdfpass;
static size_t kdfpass_sz;

static int warpsalt2priv(unsigned char *priv, unsigned char *salt, size_t salt_sz) {
  int ret;
  if ((ret = warpwallet(kdfpass, kdfpass_sz, salt, salt_sz, priv)) != 0) return ret;
  salt[salt_sz] = 0;
  return 0;
}

static int bwiosalt2priv(unsigned char *priv, unsigned char *salt, size_t salt_sz) {
  int ret;
  if ((ret = brainwalletio(kdfpass, kdfpass_sz, salt, salt_sz, priv)) != 0) return ret;
  salt[salt_sz] = 0;
  return 0;
}

static int brainv2salt2priv(unsigned char *priv, unsigned char *salt, size_t salt_sz) {
  unsigned char hexout[33];
  int ret;
  if ((ret = brainv2(kdfpass, kdfpass_sz, salt, salt_sz, hexout)) != 0) return ret;
  salt[salt_sz] = 0;
  return pass2priv(priv, hexout, sizeof(hexout)-1);
}

static int quorumsalt2priv(unsigned char *priv, unsigned char *salt, size_t salt_sz) {
  return quorum(kdfpass, kdfpass_sz, salt, salt_sz, priv);
}

static unsigned char rushchk[5];
static int rush2priv(unsigned char *priv, unsigned char *pass, size_t pass_sz) {
  SHA2_256_CTX ctx;
  unsigned char hash[SHA256_DIGEST_LENGTH];
  unsigned char userpasshash[SHA256_DIGEST_LENGTH*2+1];

  SHA2_256_Init(&ctx);
  SHA2_256_Update(&ctx, pass, pass_sz);
  SHA2_256_Final(hash, &ctx);

  hex(hash, sizeof(hash), userpasshash, sizeof(userpasshash));

  SHA2_256_Init(&ctx);
  // kdfsalt should be the fragment up to the !
  SHA2_256_Update(&ctx, kdfsalt, kdfsalt_sz);
  SHA2_256_Update(&ctx, userpasshash, 64);
  SHA2_256_Final(priv, &ctx);

  // early exit if the checksum doesn't match
  if (memcmp(priv, rushchk, sizeof(rushchk)) != 0) { return -1; }

  return 0;
}

// https://en.bitcoin.it/wiki/Mini_private_key_format
static int mini2priv(unsigned char *priv, unsigned char *pass, size_t pass_sz) {
  SHA2_256_CTX ctx;

  // validate prefix and length
  if (pass[0] != 'S' || (pass_sz != 30 && pass_sz != 22)) { return -1; }
  // spec says base58 characters, but not gonna bother checking that

  // calculated validation hash to determined whether the key is well-formed
  pass[pass_sz] = '?';
  SHA2_256_Init(&ctx);
  SHA2_256_Update(&ctx, pass, pass_sz + 1);
  SHA2_256_Final(priv, &ctx);
  pass[pass_sz] = '\0';
  // check the hash result
  if (priv[0] != '\0') { return -1; }

  return pass2priv(priv, pass, pass_sz);
}

static int wif2priv(unsigned char *priv, unsigned char *pass, size_t pass_sz) {
  unsigned char decoded[33];
  unsigned char ver;
  ssize_t ret;

  ret = b58d_chk(decoded, sizeof(decoded), pass, pass_sz, &ver);
  if (ret >= 32) {
    memcpy(priv, decoded, 32);
    return 0;
  }
  return -1;
}

// tricksy
static int script2priv(unsigned char *pub, unsigned char *script, size_t script_sz) {
  Hash160(pub, script, script_sz);
  return 0;
}

inline static void fprintresult(FILE *f, hash160_t *hash,
                                unsigned char compressed,
                                unsigned char *type,
                                unsigned char *input) {
  unsigned char hexed0[41];

  fprintf(f, "%s:%c:%s:%s\n",
          hex(hash->uc, 20, hexed0, sizeof(hexed0)),
          compressed,
          type,
          input);
}

void usage(unsigned char *name) {
  printf("Usage: %s [OPTION]...\n\n\
 -a                          open output file in append mode\n\
 -b FILE                     check for matches against bloom filter FILE\n\
 -f FILE                     verify matches against sorted hash160s in FILE\n\
 -i FILE                     read from FILE instead of stdin\n\
 -o FILE                     write to FILE instead of stdout\n\
 -c TYPES                    use TYPES for public key to hash160 computation\n\
                             multiple can be specified, for example the default\n\
                             is 'uc', which will check for both uncompressed\n\
                             and compressed addresses using Bitcoin's algorithm\n\
                             u - uncompressed address\n\
                             c - compressed address\n\
                             w - p2sh(segwit) address\n\
                             H - p2sh(uncompressed p2pkh) address\n\
                             h - p2sh(compressed p2pkh) address\n\
                             P - p2sh(uncompressed p2pk) address\n\
                             p - p2sh(compressed p2pk) address\n\
                             M - p2sh(uncompressed 1-of-1 multisig) address\n\
                             m - p2sh(compressed 1-of-1 multisig) address\n\
                             e - ethereum address\n\
                             x - most signifigant bits of x coordinate\n\
 -t TYPE                     inputs are TYPE - supported types:\n\
                             sha256 - classic brainwallet (default)\n\
                             keccak - keccak256 (ethercamp/old ethaddress)\n\
                             sha3   - sha3-256\n\
                             wif    - wallet import format\n\
                             mini   - Casascius mini private key format\n\
                             priv   - raw private keys (requires -x)\n\
                             p2sh   - raw scripts for p2sh (requires -x)\n\
                             warp   - WarpWallet (supports -s or -p)\n\
                             bwio   - brainwallet.io (supports -s or -p)\n\
                             quorum - Quorum Wallet (supports -s or -p)\n\
                             rush   - rushwallet (requires -r) FAST\n\
                             camp2  - keccak256 * 2031 (new ethercamp)\n\
                             parity - Parity Wallet 'recovery phrase' SLOW\n\
                             bv2    - brainv2 (supports -s or -p) VERY SLOW", name);
  printf("\n\
 -x                          treat input as hex encoded\n\
 -s SALT                     use SALT for salted input types (default: none)\n\
 -p PASSPHRASE               use PASSPHRASE for salted input types, inputs\n\
                             will be treated as salts\n\
 -r FRAGMENT                 use FRAGMENT for cracking rushwallet passphrase\n\
 -I HEXPRIVKEY               incremental private key cracking mode, starting\n\
                             at HEXPRIVKEY (supports -n) FAST\n\
 -D HEXPRIVKEY               doubling private key cracking mode, starting\n\
                             at HEXPRIVKEY (a bit faster than -I) FAST\n\
 -S DESCRIPTION              keystream cracking mode, input will be treated\n\
                             as a stream of raw bytes, and each possible offset\n\
                             will be tried as a private key. Output will be\n\
                             labeled with DESCRIPTION,OFFSET\n\
 -T                          don't check if input is a tty\n\
 -k K                        skip the first K lines of input\n\
 -N N                        stop after trying N keys\n\
 -n K/N                      use only the Kth of every N input lines\n\
 -N N                        stop after N input lines or keys\n\
 -B BATCH_SIZE               batch size for affine transformations\n\
                             must be a power of 2 (default/max: %d)\n\
 -w WINDOW_SIZE              window size for ecmult table (default: 16)\n\
                             uses about 3 * 2^w KiB memory on startup, but\n\
                             only about 2^w KiB once the table is built\n\
 -m FILE                     load ecmult table from FILE\n\
                             the ecmtabgen tool can build such a table\n\
 -v                          verbose - display cracking progress\n\
 -h                          show this help\n", BATCH_MAX);
//q, --quiet                 suppress non-error messages
  exit(1);
}

void set_pubhashfn(pubhashfn_t pubhashfn[], unsigned char *copt) {
  if (copt == NULL) {
    pubhashfn[0].fn = &uhash160; pubhashfn[0].id = 'u';
    pubhashfn[1].fn = &chash160; pubhashfn[1].id = 'c';
  } else {
    int i, j = 0, has_compressed = 0;

    // check for compressed P2PKH
    i = 0;
    while (copt[i]) {
      if (copt[i] == 'c') {
        has_compressed = 1;
        pubhashfn[j].fn = &chash160;
        pubhashfn[j++].id = 'c';
        break;
      }
    }

    // check for P2SH-P2WPKH
    i = 0;
    while (copt[i]) {
      if (copt[i] == 'w') {
        // use optimized version if possible
        pubhashfn[j].fn = has_compressed ? &whash160_pre : &whash160;
        pubhashfn[j++].id = 'w';
        break;
      }
    }

    i = 0;
    while (copt[i]) {
      switch (copt[i]) {
        case 'c': break; // handled in previous loop (compressed P2PKH)
        case 'w': break; // handled in previous loop (P2SH-P2WPKH)
        case 'u': pubhashfn[j].fn = &uhash160; break;
        case 'H': pubhashfn[j].fn = &Hhash160; break;
        case 'h': pubhashfn[j].fn = &hhash160; break;
        case 'P': pubhashfn[j].fn = &Phash160; break;
        case 'p': pubhashfn[j].fn = &phash160; break;
        case 'M': pubhashfn[j].fn = &Mhash160; break;
        case 'm': pubhashfn[j].fn = &mhash160; break;
        case 'e': pubhashfn[j].fn = &ehash160; break;
        case 'x': pubhashfn[j].fn = &xhash160; break;
        default: bail(1, "Unknown hash160 type '%c'.\n", copt[i]);
      }
      if (strchr(copt + i + 1, copt[i])) {
        bail(1, "Duplicate hash160 type '%c'.\n", copt[i]);
      }

      pubhashfn[j++].id = copt[i++];
    }
  }
}

int main(int argc, char **argv) {
  FILE *ifile = stdin;
  FILE *ofile = stdout;
  FILE *ffile = NULL;

  int ret, c, i, j;
#ifndef SHOW_DUPLICATE_HITS
  int k;
#endif//SHOW_DUPLICATE_HITS

  float alpha, ilines_rate, ilines_rate_avg;
  int64_t raw_lines = -1;
  uint64_t report_next = 0;
  uint64_t report_intr = 1;
  uint64_t time_last, time_curr, time_delta;
  uint64_t time_start, time_elapsed;
  uint64_t ilines_last, ilines_curr, ilines_delta;
  uint64_t Slines_last, Slines_curr;
  uint64_t olines;

  int skipping = 0, tty = 0;

  unsigned char modestr[64];

  int spok = 0, aopt = 0, vopt = 0, wopt = 16, xopt = 0;
  int nopt_mod = 0, nopt_rem = 0, Bopt = 0, Topt = 0, Jopt = -1;
  uint64_t kopt = 0, Nopt = ~0ULL;
  unsigned char *bopt = NULL, *iopt = NULL, *oopt = NULL;
  unsigned char *topt = NULL, *sopt = NULL, *popt = NULL;
  unsigned char *mopt = NULL, *fopt = NULL, *ropt = NULL;
  unsigned char *Iopt = NULL, *copt = NULL, *Sopt = NULL;
  unsigned char *Dopt = NULL;

  unsigned char Sdesc[257];

  unsigned char priv[64];
  hash160_t hash160;
  pubhashfn_t pubhashfn[32];
  memset(pubhashfn, 0, sizeof(pubhashfn));

  int batch_stopped = -1;
  char *batch_line[BATCH_MAX];
  size_t batch_line_sz[BATCH_MAX];
  int batch_line_read[BATCH_MAX];
  unsigned char batch_priv[BATCH_MAX][32];
  unsigned char batch_upub[BATCH_MAX][65];

  while ((c = getopt(argc, argv, "avxb:hi:k:f:m:n:o:p:s:r:c:t:w:I:D:S:B:N:J:T")) != -1) {
    switch (c) {
      case 'a':
        aopt = 1; // open output file in append mode
        break;
      case 'k':
        kopt = strtoull(optarg, NULL, 10); // skip first k lines of input
        skipping = 1;
        break;
      case 'n':
        // only try the rem'th of every mod lines (one indexed)
        nopt_rem = atoi(optarg) - 1;
        optarg = strchr(optarg, '/');
        if (optarg != NULL) { nopt_mod = atoi(optarg+1); }
        skipping = 1;
        break;
      case 'B':
        Bopt = atoi(optarg);
        break;
      case 'N':
        Nopt = strtoull(optarg, NULL, 0); // allows 0x
        break;
      case 'w':
        if (wopt > 1) wopt = atoi(optarg);
        break;
      case 'm':
        mopt = optarg; // table file
        wopt = 1; // auto
        break;
      case 'v':
        vopt = 1; // verbose
        break;
      case 'b':
        bopt = optarg; // bloom filter file
        break;
      case 'f':
        fopt = optarg; // full filter file
        break;
      case 'i':
        iopt = optarg; // input file
        break;
      case 'o':
        oopt = optarg; // output file
        break;
      case 'x':
        xopt = 1; // input is hex encoded
        break;
      case 's':
        sopt = optarg; // salt
        break;
      case 'p':
        popt = optarg; // passphrase
        break;
      case 'r':
        ropt = optarg; // rushwallet
        break;
      case 'c':
        copt = optarg; // type of hash160
        break;
      case 't':
        topt = optarg; // type of input
        break;
      case 'I':
        Iopt = optarg; // start key for incremental
        break;
      case 'D':
        Dopt = optarg; // start key for doubling
        break;
      case 'S':
        Sopt = optarg; // description for keystream
        break;
      case 'T':
        Topt = 1; // don't check if input is a tty
        break;
      case 'J':
        Jopt = atoi(optarg); // SHA256 engines to try
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

  if (nopt_rem != 0 || nopt_mod != 0) {
    // note that nopt_rem has had one subtracted at option parsing
    if (nopt_rem >= nopt_mod) {
      bail(1, "Invalid '-n' argument, remainder '%d' must be <= modulus '%d'\n", nopt_rem+1, nopt_mod);
    } else if (nopt_rem < 0) {
      bail(1, "Invalid '-n' argument, remainder '%d' must be > 0\n", nopt_rem+1);
    } else if (nopt_mod < 1) {
      bail(1, "Invalid '-n' argument, modulus '%d' must be > 0\n", nopt_mod);
    }
  }

  //if (wopt && mopt) {
  //  bail(1, "Window size cannot be manually specified when using an ecmult table\n");
  //} else
  /* values of 17, 21, 23, 25, 27, 28, 30, 31 just waste memory */
  if (wopt < 1 || wopt > 28) {
    bail(1, "Invalid window size '%d' - must be >= 1 and <= 28\n", wopt);
  } else {
    // very rough sanity check of window size
    struct sysinfo info;
    sysinfo(&info);
    uint64_t sysram = info.mem_unit * info.totalram;
    if (3584LLU*(1<<wopt) > sysram) {
      bail(1, "Not enough ram for requested window size '%d'\n", wopt);
    }
  }

  if (Bopt) { // if unset, will be set later
    if (Bopt < 1 || Bopt > BATCH_MAX) {
      bail(1, "Invalid '-B' argument, batch size '%d' - must be >= 1 and <= %d\n", Bopt, BATCH_MAX);
    //} else if (Bopt & (Bopt - 1)) { // https://graphics.stanford.edu/~seander/bithacks.html#DetermineIfPowerOf2
    //  bail(1, "Invalid '-B' argument, batch size '%d' is not a power of 2\n", Bopt);
    }
  }

  if (Iopt) {
    if (strlen(Iopt) != 64) {
      bail(1, "The starting key passed to the '-I' must be 64 hex digits exactly\n");
    }
    if (xopt) {
      bail(1, "Hex input not meaningful in incremental mode\n");
    }
    if (topt) {
      bail(1, "Cannot specify input type in incremental mode\n");
    }
    topt = "priv";
    // normally, getline would allocate the batch_line entries, but we need to
    // do this to give the processing loop somewhere to write to in incr mode
    for (i = 0; i < BATCH_MAX; ++i) {
      batch_line[i] = Iopt;
    }
    unhex(Iopt, sizeof(priv)*2, priv, sizeof(priv));
    skipping = 1;
    if (!nopt_mod) { nopt_mod = 1; };
  }

  if (Dopt) {
    if (strlen(Dopt) != 64) {
      bail(1, "The starting key passed to the '-D' must be 64 hex digits exactly\n");
    }
    if (xopt) {
      bail(1, "Hex input not meaningful in doubling mode\n");
    }
    if (topt) {
      bail(1, "Cannot specify input type in doubling mode\n");
    }
    if (Iopt) {
      bail(1, "Doubling mode and incremental mode cannot be used together\n");
    }
    topt = "priv";
    // normally, getline would allocate the batch_line entries, but we need to
    // do this to give the processing loop somewhere to write to in incr mode
    for (i = 0; i < BATCH_MAX; ++i) {
      batch_line[i] = Dopt;
    }
    unhex(Dopt, sizeof(priv)*2, priv, sizeof(priv));
  }

  if (Sopt) {
    if (xopt) {
      bail(1, "Hex input not supported in keystream mode\n");
    }
    if (topt) {
      bail(1, "Cannot specify input type in keystream mode\n");
    }
    if (Iopt) {
      bail(1, "Stream mode and incremental mode cannot be used together\n");
    }
    if (Iopt) {
      bail(1, "Stream mode and doubling mode cannot be used together\n");
    }
    if (strnlen(Sopt, 257) > 256) {
      bail(1, "Maximum keystream description length is 256 bytes\n");
    }

    strncpy(Sdesc, Sopt, 256);
    Sdesc[256] = 0;

    topt = "priv";

    if ((batch_line[0] = malloc(64+1+256+1+20)) == NULL) {
      bail(1, "Failed to allocate output strings\n");
    }
    for (i = 1; i < BATCH_MAX; ++i) {
      batch_line[i] = batch_line[0];
    }
  }

  /* handle copt */
  if (copt == NULL) {
    pubhashfn[0].fn = &uhash160; pubhashfn[0].id = 'u';
    pubhashfn[1].fn = &chash160; pubhashfn[1].id = 'c';
  } else {
    i = 0;
    while (copt[i]) {
      switch (copt[i]) {
        case 'u':
          pubhashfn[i].fn = &uhash160;
          break;
        case 'c':
          pubhashfn[i].fn = &chash160;
          break;
        case 'w':
          pubhashfn[i].fn = &whash160;
          break;
        case 'H':
          pubhashfn[i].fn = &Hhash160;
          break;
        case 'h':
          pubhashfn[i].fn = &hhash160;
          break;
        case 'P':
          pubhashfn[i].fn = &Phash160;
          break;
        case 'p':
          pubhashfn[i].fn = &phash160;
          break;
        case 'M':
          pubhashfn[i].fn = &Mhash160;
          break;
        case 'm':
          pubhashfn[i].fn = &mhash160;
          break;
        case 'e':
          pubhashfn[i].fn = &ehash160;
          break;
        case 'x':
          pubhashfn[i].fn = &xhash160;
          break;
        default:
          bail(1, "Unknown hash160 type '%c'.\n", copt[i]);
      }
      if (strchr(copt + i + 1, copt[i])) {
        bail(1, "Duplicate hash160 type '%c'.\n", copt[i]);
      }
      pubhashfn[i].id = copt[i];
      ++i;
    }
  }

  /* handle topt */
  if (topt == NULL) { topt = "sha256"; }

  if (strcmp(topt, "sha256") == 0) {
    input2priv = &pass2priv;
  } else if (strcmp(topt, "mini") == 0) {
    input2priv = &mini2priv;
  } else if (strcmp(topt, "wif") == 0) {
    input2priv = &wif2priv;
  } else if (strcmp(topt, "priv") == 0) {
    if (!xopt && !Sopt && !Iopt && !Dopt) {
      bail(1, "raw private key input requires -x\n");
    }
    input2priv = &rawpriv2priv;
  } else if (strcmp(topt, "p2sh") == 0) {
    if (!xopt) {
      bail(1, "raw script input requires -x\n");
    }
    if (copt) {
      bail(1, "hash160 type cannot be set for raw script input\n");
    }
    pubhashfn[0].fn = &shash160; pubhashfn[0].id = 's';
    pubhashfn[1].fn = NULL;      pubhashfn[1].id = 0x0;
    input2priv = &script2priv;
  } else if (strcmp(topt, "warp") == 0) {
    if (!Bopt) { Bopt = 1; } // don't batch transform for slow input hashes by default
    spok = 1;
    input2priv = popt ? &warpsalt2priv : &warppass2priv;
  } else if (strcmp(topt, "bwio") == 0) {
    if (!Bopt) { Bopt = 1; } // don't batch transform for slow input hashes by default
    spok = 1;
    input2priv = popt ? &bwiosalt2priv : &bwiopass2priv;
  } else if (strcmp(topt, "bv2") == 0) {
    if (!Bopt) { Bopt = 1; } // don't batch transform for slow input hashes by default
    spok = 1;
    input2priv = popt ? &brainv2salt2priv : &brainv2pass2priv;
  } else if (strcmp(topt, "quorum") == 0) {
    spok = 1;
    input2priv = popt ? &quorumsalt2priv : &quorumpass2priv;
  } else if (strcmp(topt, "rush") == 0) {
    input2priv = &rush2priv;
  } else if (strcmp(topt, "camp2") == 0) {
    input2priv = &camp2priv;
  } else if (strcmp(topt, "parity") == 0) {
    if (!Bopt) { Bopt = 1; } // don't batch transform for slow input hashes by default
    input2priv = &parity2priv;
  } else if (strcmp(topt, "keccak") == 0) {
    input2priv = &keccak2priv;
  } else if (strcmp(topt, "sha3") == 0) {
    input2priv = &sha32priv;
  } else {
    bail(1, "Unknown input type '%s'.\n", topt);
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
        kdfsalt = chkmalloc(0);
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

  if (ropt) {
    if (input2priv != &rush2priv) {
      bail(1, "Specifying a url fragment only supported with input type 'rush'\n");
    }
    kdfsalt = ropt;
    kdfsalt_sz = strlen(kdfsalt) - sizeof(rushchk)*2;
    if (kdfsalt[kdfsalt_sz-1] != '!') {
      bail(1, "Invalid rushwallet url fragment '%s'\n", kdfsalt);
    }
    unhex(kdfsalt+kdfsalt_sz, sizeof(rushchk)*2, rushchk, sizeof(rushchk));
    kdfsalt[kdfsalt_sz] = '\0';
  } else if (input2priv == &rush2priv) {
    bail(1, "The '-r' option is required for rushwallet.\n");
  }

  snprintf(modestr, sizeof(modestr), xopt ? "(hex)%s" : "%s", topt);

  if (bopt) {
    if ((ret = mmapf(&bloom_mmapf, bopt, BLOOM_SIZE, MMAPF_RNDRD)) != MMAPF_OKAY) {
      bail(1, "failed to open bloom filter '%s': %s\n", bopt, mmapf_strerror(ret));
    } else if (bloom_mmapf.mem == NULL) {
      bail(1, "got NULL pointer trying to set up bloom filter\n");
    }
    bloom = bloom_mmapf.mem;
  }

  if (fopt) {
    if (!bopt) {
      bail(1, "The '-f' option must be used with a bloom filter\n");
    }
    if ((ffile = fopen(fopt, "r")) == NULL) {
      bail(1, "failed to open '%s' for reading: %s\n", fopt, strerror(errno));
    }
  }

  if (iopt) {
    if ((ifile = fopen(iopt, "r")) == NULL) {
      bail(1, "failed to open '%s' for reading: %s\n", iopt, strerror(errno));
    }
    // increases readahead window, don't really care if it fails
    posix_fadvise(fileno(ifile), 0, 0, POSIX_FADV_SEQUENTIAL);
  } else {
    // people keep filing github issues about brainflayer not doing anything
    if (!Topt && !Iopt && isatty(fileno(stdin))) {
      fprintf(stderr, "WARNING: Reading from a tty. Unless you intend to type candidate passphrases,\n");
      fprintf(stderr, "this is probably not what you want. Try piping input or using `-i FILE`.\n");
      fprintf(stderr, "To disable this check, use the `-T` option.\n\n");
      if (!Bopt) {
        fprintf(stderr, "Affine transform batching disabled for tty input, performance will suffer.\n\n");
        Bopt = 1;
      }

    }
  }

  if (oopt && (ofile = fopen(oopt, (aopt ? "a" : "w"))) == NULL) {
    bail(1, "failed to open '%s' for writing: %s\n", oopt, strerror(errno));
  }

  /* line buffer output */
  setvbuf(ofile,  NULL, _IOLBF, 0);
  /* line buffer stderr */
  setvbuf(stderr, NULL, _IOLBF, 0);

  if (vopt && ofile == stdout && isatty(fileno(stdout))) { tty = 1; }

  // INIT GLOBALS
  SHA2_256_Register(Jopt);
  /* initialize buffers */
  mem = chkmalloc(4096);
#ifndef SHOW_DUPLICATE_HITS
  hits = chkmalloc(20 * hits_max);
#endif//SHOW_DUPLICATE_HITS
  unhexed = chkmalloc(unhexed_sz);
  //brainflayer_init_globals();

  if (secp256k1_ec_pubkey_precomp_table(wopt, mopt) != 0) {
    bail(1, "failed to initialize precomputed table\n");
  }

  if (secp256k1_ec_pubkey_batch_init(BATCH_MAX) != 0) {
    bail(1, "failed to initialize batch point conversion structures\n");
  }

  ilines_curr = 0;

  if (vopt) {
    /* initialize timing data */
    time_start = time_last = getns();
    olines = ilines_last = 0;
    ilines_rate_avg = -1;
    alpha = 0.500;
  } else {
    time_start = time_last = 0; // prevent compiler warning about uninitialized use
  }

  // set default batch size
  if (!Bopt) { Bopt = BATCH_MAX; }

  // needs to be done fairly late...
  if (Sopt) {
    ks_tables_init();
    if (fread(keystream + Bopt, 1, 31, ifile) != 31) {
      bail(1, "could not read enough bytes from to initialize keystream\n");
    }
    Slines_last = Slines_curr = 0;
  }

  for (;;) {
    if (Iopt) {
      if (skipping) {
        priv_add_uint32(priv, nopt_rem + kopt);
        skipping = 0;
      }
      secp256k1_ec_pubkey_batch_incr(Bopt, nopt_mod, batch_upub, batch_priv, priv);
      memcpy(priv, batch_priv[Bopt-1], 32);
      priv_add_uint32(priv, nopt_mod);

      batch_stopped = Bopt;
    } else if (Dopt) {
      secp256k1_ec_pubkey_batch_double(Bopt, batch_upub, batch_priv, priv);
      memcpy(priv, batch_priv[Bopt-1], 32);
      priv_double(priv);

      batch_stopped = Bopt;
    } else if (Sopt) {
      Slines_last = Slines_curr;
      // copy remaing bytes from last round to front of stream
      memcpy(keystream, keystream + Bopt, 31);
      batch_stopped = fread(keystream+31, 1, Bopt, ifile);
      fprintf(stderr, "%s\n", hex(keystream, 32, batch_line[0], 65));
      if (batch_stopped <= 0) {
        batch_stopped = 0;
        break;
      } else {
        secp256k1_ec_pubkey_batch_stream(batch_stopped, batch_upub, batch_priv, keystream);
        Slines_curr += batch_stopped;
      }
    } else {
      for (i = 0; i < Bopt; ++i) {
        if ((batch_line_read[i] = getline(&batch_line[i], &batch_line_sz[i], ifile)-1) > -1) {
          if (skipping) {
            ++raw_lines;
            if (kopt && raw_lines < kopt) { --i; continue; }
            if (nopt_mod && raw_lines % nopt_mod != nopt_rem) { --i; continue; }
          }
        } else {
          break;
        }
        batch_line[i][batch_line_read[i]] = 0;
        if (xopt) {
          if (batch_line_read[i] / 2 > unhexed_sz) {
            unhexed_sz = batch_line_read[i];
            unhexed = chkrealloc(unhexed, unhexed_sz);
          }
          // rewrite the input line from hex
          unhex(batch_line[i], batch_line_read[i], unhexed, unhexed_sz);
          if (input2priv == &script2priv) {
            if (script2priv(batch_upub[i], unhexed, batch_line_read[i]/2) != 0) {
              //fprintf(stderr, "script2priv failed! continuing...\n");
              // skip this key
              ++ilines_curr; --i;
            }
          } else {
            if (input2priv(batch_priv[i], unhexed, batch_line_read[i]/2) != 0) {
              //fprintf(stderr, "input2priv failed! continuing...\n");
              // skip this key
              ++ilines_curr; --i;
            }
          }
        } else {
          if (input2priv(batch_priv[i], batch_line[i], batch_line_read[i]) != 0) {
            //fprintf(stderr, "input2priv failed! continuing...\n");
            // skip this key
            ++ilines_curr; --i;
          }
        }
      }

      if (input2priv != &script2priv) {
        // batch compute the public keys
        secp256k1_ec_pubkey_batch_create(Bopt, batch_upub, batch_priv);
      }

      // save ending value from read loop
      batch_stopped = i;
    }

    // loop over the public keys
    for (i = 0; i < batch_stopped; ++i) {
      if (bloom) { /* crack mode */
        // loop over pubkey hash functions
        for (j = 0; pubhashfn[j].fn != NULL; ++j) {
          pubhashfn[j].fn(&hash160, batch_upub[i]);

#if 0
          if (bloom_chk_hash160(bloom, hash160.ul) == 0) { continue; }
#else
          unsigned int bit;
          bit = BH00(hash160.ul); if (BLOOM_GET_BIT(bit) == 0) { continue; }
          bit = BH01(hash160.ul); if (BLOOM_GET_BIT(bit) == 0) { continue; }
          bit = BH02(hash160.ul); if (BLOOM_GET_BIT(bit) == 0) { continue; }
          bit = BH03(hash160.ul); if (BLOOM_GET_BIT(bit) == 0) { continue; }
          bit = BH04(hash160.ul); if (BLOOM_GET_BIT(bit) == 0) { continue; }
          bit = BH05(hash160.ul); if (BLOOM_GET_BIT(bit) == 0) { continue; }
          bit = BH06(hash160.ul); if (BLOOM_GET_BIT(bit) == 0) { continue; }
          bit = BH07(hash160.ul); if (BLOOM_GET_BIT(bit) == 0) { continue; }
          bit = BH08(hash160.ul); if (BLOOM_GET_BIT(bit) == 0) { continue; }
          bit = BH09(hash160.ul); if (BLOOM_GET_BIT(bit) == 0) { continue; }
          bit = BH10(hash160.ul); if (BLOOM_GET_BIT(bit) == 0) { continue; }
          bit = BH11(hash160.ul); if (BLOOM_GET_BIT(bit) == 0) { continue; }
          bit = BH12(hash160.ul); if (BLOOM_GET_BIT(bit) == 0) { continue; }
          bit = BH13(hash160.ul); if (BLOOM_GET_BIT(bit) == 0) { continue; }
          bit = BH14(hash160.ul); if (BLOOM_GET_BIT(bit) == 0) { continue; }
          bit = BH15(hash160.ul); if (BLOOM_GET_BIT(bit) == 0) { continue; }
          bit = BH16(hash160.ul); if (BLOOM_GET_BIT(bit) == 0) { continue; }
          bit = BH17(hash160.ul); if (BLOOM_GET_BIT(bit) == 0) { continue; }
          bit = BH18(hash160.ul); if (BLOOM_GET_BIT(bit) == 0) { continue; }
          bit = BH19(hash160.ul); if (BLOOM_GET_BIT(bit) == 0) { continue; }
#endif

          if (!fopt || hsearchf(ffile, &hash160)) {
#ifndef SHOW_DUPLICATE_HITS
            // look for duplicates
            for (k = 0; k < olines; ++k) {
              if (memcmp(hits + (k*20), &hash160, 20) == 0) {
                k = -1;
                break;
              }
            }
            if (k >= 0) {
#else
            if (1) {
#endif//SHOW_DUPLICATE_HITS
              if (tty) { fprintf(ofile, "\033[0K"); }
              // reformat/populate the line if required
              if (Iopt || Dopt) {
                hex(batch_priv[i], 32, batch_line[i], 65);
              } else if (Sopt) {
                hex(batch_priv[i], 32, batch_line[i], 65);
                sprintf(batch_line[i]+64, ":%s,%zu", Sdesc, Slines_last + i);
              }
              fprintresult(ofile, &hash160, pubhashfn[j].id, modestr, batch_line[i]);
#ifndef SHOW_DUPLICATE_HITS
              if (k < hits_max) { memcpy(hits + (k*20), &hash160, 20); }
#endif//SHOW_DUPLICATE_HITS
              ++olines;
            }
#if 0 // brace balance...
          }
#else
          }
#endif
        }
      } else { /* generate mode */
        // reformat/populate the line if required
        if (Iopt || Dopt) {
          hex(batch_priv[i], 32, batch_line[i], 65);
        } else if (Sopt) {
          hex(batch_priv[i], 32, batch_line[i], 65);
          sprintf(batch_line[i]+64, ":%s,%zu", Sdesc, Slines_last + i);
        }
        j = 0;
        while (pubhashfn[j].fn != NULL) {
          pubhashfn[j].fn(&hash160, batch_upub[i]);
          fprintresult(ofile, &hash160, pubhashfn[j].id, modestr, batch_line[i]);
          ++j;
        }
      }
    }
    // end public key processing loop

    ilines_curr += batch_stopped;

    // start stats
    if (vopt) {
      if (batch_stopped < Bopt || ilines_curr >= Nopt || ilines_curr >= report_next) {
        time_curr = getns();
        time_delta = time_curr - time_last;
        time_elapsed = time_curr - time_start;
        time_last = time_curr;
        ilines_delta = ilines_curr - ilines_last;
        ilines_last = ilines_curr;
        ilines_rate = (ilines_delta * 1.0e9) / (time_delta * 1.0);

        if (batch_stopped < Bopt) {
          /* report overall average on last status update */
          ilines_rate_avg = (ilines_curr * 1.0e9) / (time_elapsed * 1.0);
        } else if (ilines_rate_avg < 0) {
          ilines_rate_avg = ilines_rate;
        /* target reporting frequency to about once every five seconds */
        } else if (time_delta < 2500000000) {
          report_intr = report_intr << 1;
          ilines_rate_avg = ilines_rate; /* reset EMA */
        } else if (time_delta > 10000000000) {
          if (report_intr > 1) { report_intr >>= 1; }
          ilines_rate_avg = ilines_rate; /* reset EMA */
        } else {
          /* exponetial moving average */
          ilines_rate_avg = alpha * ilines_rate + (1 - alpha) * ilines_rate_avg;
        }

        report_next = ilines_curr + report_intr;

        fprintf(stderr,
            "\033[0G\033[2K"
            " rate: %9.2f p/s"
            " found: %5zu/%-10zu"
            " elapsed: %8.3f s"
            "\033[0G",
            ilines_rate_avg,
            olines,
            ilines_curr,
            time_elapsed / 1.0e9
        );

        fflush(stderr);
      }
    }
    // end stats

    // main loop exit condition
    if (batch_stopped < Bopt || ilines_curr >= Nopt) {
      if (vopt) { fprintf(stderr, "\n"); }
      break;
    }
  }

  return 0;
}

/*  vim: set ts=2 sw=2 et ai si: */
