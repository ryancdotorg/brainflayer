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

#include <sys/time.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/sysinfo.h>

#include "ripemd160_256.h"

#include "ec_pubkey_fast.h"

#include "hex.h"
#include "bloom.h"
#include "mmapf.h"
#include "hash160.h"
#include "hsearchf.h"

#include "brainv2.h"
#include "warpwallet.h"
#include "brainwalletio.h"

static int brainflayer_is_init = 0;

static unsigned char hash256[SHA256_DIGEST_LENGTH];
static unsigned char priv256[SHA256_DIGEST_LENGTH];
static hash160_t hash160_compr;
static hash160_t hash160_uncmp;
static unsigned char *mem;

static mmapf_ctx bloom_mmapf;
static unsigned char *bloom = NULL;

static unsigned char hexed0[41];
static unsigned char hexed1[41];
static unsigned char hexed2[65];

static unsigned char *unhexed = NULL;
static size_t unhexed_sz = 4096;

static SHA256_CTX    *sha256_ctx;

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

static inline void brainflayer_init_globals() {
  /* only initialize stuff once */
  if (!brainflayer_is_init) {
    /* initialize buffers */
    mem = chkmalloc(4096);
    unhexed = chkmalloc(unhexed_sz);

    /* initialize hashs */
    sha256_ctx = chkmalloc(sizeof(*sha256_ctx));

    /* set the flag */
    brainflayer_is_init = 1;
  }
}

inline static int pub2hash160(unsigned char *pub_chr) {
  /* compute hash160 for uncompressed public key */
  /* sha256(pub) */
  SHA256_Init(sha256_ctx);
  SHA256_Update(sha256_ctx, pub_chr, 65);
  SHA256_Final(hash256, sha256_ctx);
  /* ripemd160(sha256(pub)) */
  ripemd160_256(hash256, hash160_uncmp.uc);

  /* quick and dirty public key compression */
  pub_chr[0] = 0x02 | (pub_chr[64] & 0x01);

  /* compute hash160 for compressed public key */
  /* sha256(pub) */
  SHA256_Init(sha256_ctx);
  SHA256_Update(sha256_ctx, pub_chr, 33);
  SHA256_Final(hash256, sha256_ctx);
  /* ripemd160(sha256(pub)) */
  ripemd160_256(hash256, hash160_compr.uc);

  return 0;
}

inline static int priv_incr(unsigned char *priv) {
  unsigned char *pub_chr = mem;
  int pub_chr_sz;

  secp256k1_ec_pubkey_incr(pub_chr, &pub_chr_sz, priv);

  return pub2hash160(pub_chr);
}

inline static int priv2hash160(unsigned char *priv) {
  unsigned char *pub_chr = mem;
  int pub_chr_sz;

  secp256k1_ec_pubkey_create_precomp(pub_chr, &pub_chr_sz, priv);

  return pub2hash160(pub_chr);
}

static int pass2hash160(unsigned char *pass, size_t pass_sz) {
  /* privkey = sha256(passphrase) */
  SHA256_Init(sha256_ctx);
  SHA256_Update(sha256_ctx, pass, pass_sz);
  SHA256_Final(priv256, sha256_ctx);

  return priv2hash160(priv256);
}

static int hexpass2hash160(unsigned char *hpass, size_t hpass_sz) {
  if (hpass_sz / 2 > unhexed_sz) {
    unhexed_sz = hpass_sz * 3;
    unhexed = chkrealloc(unhexed, unhexed_sz);
  }
  return pass2hash160(unhex(hpass, hpass_sz, unhexed, unhexed_sz), hpass_sz>>1);
}

static int hexpriv2hash160(unsigned char *hpriv, size_t hpriv_sz) {
  return priv2hash160(unhex(hpriv, hpriv_sz, priv256, sizeof(priv256)));
}

static unsigned char *kdfsalt;
static size_t kdfsalt_sz;

static int warppass2hash160(unsigned char *pass, size_t pass_sz) {
  int ret;
  if ((ret = warpwallet(pass, pass_sz, kdfsalt, kdfsalt_sz, priv256)) != 0) return ret;
  pass[pass_sz] = 0;
  return priv2hash160(priv256);
}

static int bwiopass2hash160(unsigned char *pass, size_t pass_sz) {
  int ret;
  if ((ret = brainwalletio(pass, pass_sz, kdfsalt, kdfsalt_sz, priv256)) != 0) return ret;
  pass[pass_sz] = 0;
  return priv2hash160(priv256);
}

static int brainv2pass2hash160(unsigned char *pass, size_t pass_sz) {
  unsigned char hexout[33];
  int ret;
  if ((ret = brainv2(pass, pass_sz, kdfsalt, kdfsalt_sz, hexout)) != 0) return ret;
  pass[pass_sz] = 0;
  return pass2hash160(hexout, sizeof(hexout)-1);
}

static unsigned char *kdfpass;
static size_t kdfpass_sz;

static int warpsalt2hash160(unsigned char *salt, size_t salt_sz) {
  int ret;
  if ((ret = warpwallet(kdfpass, kdfpass_sz, salt, salt_sz, priv256)) != 0) return ret;
  salt[salt_sz] = 0;
  return priv2hash160(priv256);
}

static int bwiosalt2hash160(unsigned char *salt, size_t salt_sz) {
  int ret;
  if ((ret = brainwalletio(kdfpass, kdfpass_sz, salt, salt_sz, priv256)) != 0) return ret;
  salt[salt_sz] = 0;
  return priv2hash160(priv256);
}

static int brainv2salt2hash160(unsigned char *salt, size_t salt_sz) {
  unsigned char hexout[33];
  int ret;
  if ((ret = brainv2(kdfpass, kdfpass_sz, salt, salt_sz, hexout)) != 0) return ret;
  salt[salt_sz] = 0;
  return pass2hash160(hexout, sizeof(hexout)-1);
}

static unsigned char rushchk[5];
static int rush2hash160(unsigned char *pass, size_t pass_sz) {
  unsigned char userpasshash[SHA256_DIGEST_LENGTH*2+1];

  SHA256_Init(sha256_ctx);
  SHA256_Update(sha256_ctx, pass, pass_sz);
  SHA256_Final(hash256, sha256_ctx);

  hex(hash256, sizeof(hash256), userpasshash, sizeof(userpasshash));

  SHA256_Init(sha256_ctx);
  // kdfsalt should be the fragment up to the !
  SHA256_Update(sha256_ctx, kdfsalt, kdfsalt_sz);
  SHA256_Update(sha256_ctx, userpasshash, 64);
  SHA256_Final(priv256, sha256_ctx);

  // early exit if the checksum doesn't match
  if (memcmp(priv256, rushchk, sizeof(rushchk)) != 0) { return -1; }

  return priv2hash160(priv256);
}

// function pointer
static int (*input2hash160)(unsigned char *, size_t);

inline static void fprintresult(FILE *f, hash160_t *hash,
                                unsigned char compressed,
                                unsigned char *type,
                                unsigned char *input) {
  fprintf(f, "%s:%c:%s:%s\n",
          hex(hash->uc, 20, hexed0, sizeof(hexed0)),
          compressed,
          type,
          input);
}

inline static void fprintlookup(FILE *f,
                                hash160_t *hashu,
                                hash160_t *hashc,
                                unsigned char *priv,
                                unsigned char *type,
                                unsigned char *input) {
  fprintf(f, "%s:%s:%s:%s:%s\n",
          hex(hashu->uc, 20, hexed0, sizeof(hexed0)),
          hex(hashc->uc, 20, hexed1, sizeof(hexed1)),
          hex(priv, 32, hexed2, sizeof(hexed2)),
          type,
          input);
}

void usage(unsigned char *name) {
  printf("Usage: %s [OPTION]...\n\n\
 -a                          open output file in append mode\n\
 -b FILE                     check for matches against bloom filter FILE\n\
 -f FILE                     verify matches against sorted hash160s in FILE\n\
 -L                          use single line mode for table output\n\
 -i FILE                     read from FILE instead of stdin\n\
 -o FILE                     write to FILE instead of stdout\n\
 -t TYPE                     inputs are TYPE - supported types:\n\
                             str (default) - classic brainwallet passphrases\n\
                             hex  - classic brainwallets (hex encoded)\n\
                             priv - hex encoded private keys\n\
                             warp - WarpWallet (supports -s or -p)\n\
                             bwio - brainwallet.io (supports -s or -p)\n\
                             bv2  - brainv2 (supports -s or -p) VERY SLOW\n\
                             rush - rushwallet (needs -r) FAST\n\
 -s SALT                     use SALT for salted input types (default: none)\n\
 -p PASSPHRASE               use PASSPHRASE for salted input types, inputs\n\
                             will be treated as salts\n\
 -r FRAGMENT                 use FRAGMENT for cracking rushwallet passphrase\n\
 -I HEXPRIVKEY               incremental private key cracking mode, starting\n\
                             at HEXPRIVKEY (supports -n) FAST\n\
 -k K                        skip the first K lines of input\n\
 -n K/N                      use only the Kth of every N input lines\n\
 -w WINDOW_SIZE              window size for ecmult table (default: 16)\n\
                             uses about 3 * 2^w KiB memory on startup, but\n\
                             only about 2^w KiB once the table is built\n\
 -m FILE                     load ecmult table from FILE\n\
                             the ecmtabgen tool can build such a table\n\
 -v                          verbose - display cracking progress\n\
 -h                          show this help\n", name);
//q, --quiet                 suppress non-error messages
  exit(1);
}

int main(int argc, char **argv) {
  FILE *ifile = stdin;
  FILE *ofile = stdout;
  FILE *ffile = NULL;

  int ret;

  float alpha, ilines_rate, ilines_rate_avg;
  int64_t raw_lines = -1;
  uint64_t report_mask = 0;
  uint64_t time_last, time_curr, time_delta;
  uint64_t time_start, time_elapsed;
  uint64_t ilines_last, ilines_curr, ilines_delta;
  uint64_t olines;

  int skipping = 0, tty = 0;

  char *line = NULL;
  size_t line_sz = 0;
  int line_read = 0;

  int c, spok = 0, aopt = 0, vopt = 0, wopt = 16, Lopt = 0;
  int nopt_mod = 0, nopt_rem = 0;
  uint64_t kopt = 0;
  unsigned char *bopt = NULL, *iopt = NULL, *oopt = NULL;
  unsigned char *topt = NULL, *sopt = NULL, *popt = NULL;
  unsigned char *mopt = NULL, *fopt = NULL, *ropt = NULL;
  unsigned char *Iopt = NULL;

  while ((c = getopt(argc, argv, "avb:hi:k:f:m:n:o:p:s:r:t:w:I:L")) != -1) {
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
      case 's':
        sopt = optarg; // salt
        break;
      case 'p':
        popt = optarg; // passphrase
        break;
      case 'r':
        ropt = optarg; // rushwallet
        break;
      case 't':
        topt = optarg; // type of input
        break;
      case 'I':
        Iopt = optarg; // start key for incremental
        break;
      case 'L':
        Lopt = 1; // lookup output
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

  if (Iopt) {
    if (strlen(Iopt) != 64) {
      bail(1, "The starting key passed to the '-I' must be 64 hex digits exactly\n");
    }
    if (topt) {
      bail(1, "Cannot specify input type in incremental mode\n");
    }
    topt = "priv";
    line = Iopt;
    unhex(Iopt, sizeof(priv256)*2, priv256, sizeof(priv256));
    skipping = 1;
    if (!nopt_mod) { nopt_mod = 1; };
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
    } else if (strcmp(topt, "bv2") == 0) {
      spok = 1;
      input2hash160 = popt ? &brainv2salt2hash160 : &brainv2pass2hash160;
    } else if (strcmp(topt, "rush") == 0) {
      input2hash160 = &rush2hash160;
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
    if (input2hash160 != &rush2hash160) {
      bail(1, "Specifying a url fragment only supported with input type 'rush'\n");
    }
    kdfsalt = ropt;
    kdfsalt_sz = strlen(kdfsalt) - sizeof(rushchk)*2;
    if (kdfsalt[kdfsalt_sz-1] != '!') {
      bail(1, "Invalid rushwallet url fragment '%s'\n", kdfsalt);
    }
    unhex(kdfsalt+kdfsalt_sz, sizeof(rushchk)*2, rushchk, sizeof(rushchk));
    kdfsalt[kdfsalt_sz] = '\0';
  } else if (input2hash160 == &rush2hash160) {
    bail(1, "The '-r' option is required for rushwallet.\n");
  }

  if (bopt) {
    if (Lopt) {
      bail(1, "The '-L' option cannot be used with a bloom filter\n");
    }
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
  }

  if (oopt && (ofile = fopen(oopt, (aopt ? "a" : "w"))) == NULL) {
    bail(1, "failed to open '%s' for writing: %s\n", oopt, strerror(errno));
  }

  /* line buffer output */
  setvbuf(ofile,  NULL, _IOLBF, 0);
  /* line buffer stderr */
  setvbuf(stderr, NULL, _IOLBF, 0);

  if (vopt && ofile == stdout && isatty(fileno(stdout))) { tty = 1; }

  brainflayer_init_globals();

  if (secp256k1_ec_pubkey_precomp_table(wopt, mopt) != 0) {
    bail(1, "failed to initialize precomputed table\n");
  }

  if (vopt) {
    /* initialize timing data */
    time_start = time_last = getns();
    olines = ilines_last = ilines_curr = 0;
    ilines_rate_avg = -1;
    alpha = 0.500;
  } else {
    time_start = time_last = 0; // prevent compiler warning about uninitialized use
  }

  for (;;) {
    if (Iopt) {
      if (!skipping) {
        priv_incr(priv256);
      } else {
        priv_add_uint32(priv256, nopt_rem);
        secp256k1_ec_pubkey_incr_init(priv256, nopt_mod);
        priv2hash160(priv256);
        skipping = 0;
        line_read = 1;
      }
    } else if ((line_read = getline(&line, &line_sz, ifile)-1) > -1) {
      if (skipping) {
        ++raw_lines;
        if (kopt && raw_lines < kopt) { continue; }
        if (nopt_mod && raw_lines % nopt_mod != nopt_rem) { continue; }
      }
      line[line_read] = 0;
      if (input2hash160(line, line_read) != 0) {
        goto loop_update_stats;
      }
    } else {
      if (!vopt) break;
      goto loop_update_stats;
    }

    if (bloom) {
      if (bloom_chk_hash160(bloom, hash160_uncmp.ul)) {
        if (!fopt || hsearchf(ffile, &hash160_uncmp)) {
          if (tty) { fprintf(ofile, "\033[0K"); }
          if (Iopt) { hex(priv256, 32, line, 65); }
          fprintresult(ofile, &hash160_uncmp, 'u', topt, line);
          ++olines;
        }
      }
      if (bloom_chk_hash160(bloom, hash160_compr.ul)) {
        if (!fopt || hsearchf(ffile, &hash160_compr)) {
          if (tty) { fprintf(ofile, "\033[0K"); }
          if (Iopt) { hex(priv256, 32, line, 65); }
          fprintresult(ofile, &hash160_compr, 'c', topt, line);
          ++olines;
        }
      }
    } else {
      if (Iopt) { hex(priv256, 32, line, 65); }
      if (Lopt) {
        fprintlookup(ofile, &hash160_uncmp, &hash160_compr, priv256, topt, line);
      } else {
        fprintresult(ofile, &hash160_uncmp, 'u', topt, line);
        fprintresult(ofile, &hash160_compr, 'c', topt, line);
      }
    }

loop_update_stats:
    if (vopt) {
      ++ilines_curr;
      if (line_read < 0 || (ilines_curr & report_mask) == 0) {
        time_curr = getns();
        time_delta = time_curr - time_last;
        time_elapsed = time_curr - time_start;
        time_last = time_curr;
        ilines_delta = ilines_curr - ilines_last;
        ilines_last = ilines_curr;
        ilines_rate = (ilines_delta * 1.0e9) / (time_delta * 1.0);

        if (line_read < 0) {
          /* report overall average on last status update */
          ilines_rate_avg = (--ilines_curr * 1.0e9) / (time_elapsed * 1.0);
        } else if (ilines_rate_avg < 0) {
          ilines_rate_avg = ilines_rate;
        /* target reporting frequency to about once every five seconds */
        } else if (time_delta < 2500000000) {
          report_mask = (report_mask << 1) | 1;
          ilines_rate_avg = ilines_rate; /* reset EMA */
        } else if (time_delta > 10000000000) {
          report_mask >>= 1;
          ilines_rate_avg = ilines_rate; /* reset EMA */
        } else {
          /* exponetial moving average */
          ilines_rate_avg = alpha * ilines_rate + (1 - alpha) * ilines_rate_avg;
        }

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

        if (line_read < 0) {
          fprintf(stderr, "\n");
          break;
        } else {
          fflush(stderr);
        }
      }
    }
  }

  return 0;
}

/*  vim: set ts=2 sw=2 et ai si: */
