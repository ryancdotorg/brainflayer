#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <stdio.h>
#include <fcntl.h>

#include <sys/stat.h>
#include <sys/types.h>

#include <arpa/inet.h> /*  for ntohl/htonl */

#include "bloom.h"
#include "hash160.h"

int main(int argc, char **argv) {
  hash160_t hash;
  unsigned char *bloom, *hashfile, *bloomfile;
  FILE *f, *b;
  size_t line_sz = 1024;
  char *line;
  struct stat sb;

  if (argc != 3) {
    fprintf(stderr, "[!] Usage: %s hashfile.hex bloomfile.blf\n", argv[0]);
    exit(1);
  }

  hashfile = argv[1];
  bloomfile = argv[2];

  if ((f = fopen(hashfile, "r")) == NULL) {
    fprintf(stderr, "[!] Failed to open hash160 file '%s'\n", hashfile);
    exit(1);
  }

  if ((bloom = malloc(BLOOM_SIZE)) == NULL) {
    fprintf(stderr, "[!] malloc failed (bloom filter)\n");
    exit(1);
  }

  if (stat(bloomfile, &sb) == 0) {
    if (!S_ISREG(sb.st_mode) || sb.st_size != BLOOM_SIZE) {
      fprintf(stderr, "[!] Bloom filter file '%s' is not the correct size (%ju != %d)\n", bloomfile, sb.st_size, BLOOM_SIZE);
      exit(1);
    }
    if ((b = fopen(bloomfile, "r+")) == NULL) {
      fprintf(stderr, "[!] Failed to open bloom filter file '%s' for read/write\n", bloomfile);
      exit(1);
    }
    fprintf(stderr, "[*] Reading existing bloom filter from '%s'...\n", bloomfile);
    if ((fread(bloom, BLOOM_SIZE, 1, b)) != 1 || (fseek(b, 0, SEEK_SET)) != 0) {
      fprintf(stderr, "[!] Failed to read existing boom filter from '%s'\n", bloomfile);
      exit(1);
    }
  } else {
    /*  Assume the file didn't exist - yes there is a race condition */
    if ((b = fopen(bloomfile, "w+")) == NULL) {
      fprintf(stderr, "[!] Failed to create bloom filter file '%s'\n", bloomfile);
      exit(1);
    }
    // start it empty
    fprintf(stderr, "[*] Initializing bloom filter...\n");
    memset(bloom, 0, BLOOM_SIZE);
  }


  if ((line = malloc(line_sz+1)) == NULL) {
    fprintf(stderr, "[!] malloc failed (line buffer)\n");
    exit(1);
  }
  
  fprintf(stderr, "[*] Loading hash160s from '%s'... (this may take a few minutes)\n", hashfile);
  while (getline(&line, &line_sz, f) > 0) {
    if (sscanf(line, "%08x%08x%08x%08x%08x", &hash.ul[0],
        &hash.ul[1], &hash.ul[2], &hash.ul[3], &hash.ul[4])) {
      /* fix the byte order */
      hash.ul[0] = htonl(hash.ul[0]);
      hash.ul[1] = htonl(hash.ul[1]);
      hash.ul[2] = htonl(hash.ul[2]);
      hash.ul[3] = htonl(hash.ul[3]);
      hash.ul[4] = htonl(hash.ul[4]);
      bloom_set_hash160(bloom, hash.ul);
    }
  }

  fprintf(stderr, "[*] Writing bloom filter to '%s'...\n", bloomfile);
  if ((fwrite(bloom, BLOOM_SIZE, 1, b)) != 1) {
    fprintf(stderr, "[!] Failed to write bloom filter file '%s'\n", bloomfile);
    exit(1);
  }
  
  fprintf(stderr, "[+] Success!\n");
  return 0;
}

/*  vim: set ts=2 sw=2 et ai si: */
