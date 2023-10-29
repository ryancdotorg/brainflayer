// SHA-256 implemetation, transform only
// The `sha256_xform_internal` function here is based on the function
// `sha256_process` from public domain code in md5deep/hashdeep, originally
// written by Christophe Devine.
//
// The code has been modified to match the API of Intel's optimized assembly
// implementations of SHA256. Rather than a context struct, a simple array of
// uint32s is used to hold the state, and an argument to specify the number of
// blocks to process has been added.
//
// Modifications by Ryan Castellucci, all changes in public domain

#include <stdint.h>
#include <endian.h>

// Process input in chunks of 64 bytes, caller resposible for padding
static void sha256_256(uint32_t *digest, const char *data)
{
  const uint32_t *input=(uint32_t *)data;
  uint32_t temp1, temp2, W[16];
  uint32_t A, B, C, D, E, F, G, H;
  int i;

#define ROR(x,n) __extension__({ uint32_t _x=(x), _n=(n); (_x >> _n) | (_x << (32-_n)); })

#define S0(x) (ROR(x, 7) ^ ROR(x,18) ^ (x >> 3))
#define S1(x) (ROR(x,17) ^ ROR(x,19) ^ (x >> 10))

#define S2(x) (ROR(x, 2) ^ ROR(x,13) ^ ROR(x,22))
#define S3(x) (ROR(x, 6) ^ ROR(x,11) ^ ROR(x,25))

#define F0(x,y,z) ((x & y) | (z & (x | y)))
#define F1(x,y,z) (z ^ (x & (y ^ z)))

#define R(t)                                  \
(                                             \
  W[t] = S1(W[(t+14)&15]) + W[(t+9)&15] +     \
         S0(W[(t+1)&15]) + W[t]               \
)

#define P(a,b,c,d,e,f,g,h,x,K)                \
{                                             \
  temp1 = h + S3(e) + F1(e,f,g) + K + x;      \
  temp2 = S2(a) + F0(a,b,c);                  \
  d += temp1; h = temp1 + temp2;              \
}                                             \

  for (;;) {
    /* Load input */
    for (i = 0; i < 8; ++i) {
      W[i] = htobe32(input[i]);
    }

    W[ 8] = be32toh(0x80000000);
    W[ 9] = 0; W[10] = 0; W[11] = 0;
    W[12] = 0; W[13] = 0; W[14] = 0;
    W[15] = be32toh(0x00000100);

    A = 0x6a09e667; B = 0xbb67ae85;
    C = 0x3c6ef372; D = 0xa54ff53a;
    E = 0x510e527f; F = 0x9b05688c;
    G = 0x1f83d9ab; H = 0x5be0cd19;

    P(A, B, C, D, E, F, G, H, W[ 0], 0x428a2f98);
    P(H, A, B, C, D, E, F, G, W[ 1], 0x71374491);
    P(G, H, A, B, C, D, E, F, W[ 2], 0xb5c0fbcf);
    P(F, G, H, A, B, C, D, E, W[ 3], 0xe9b5dba5);
    P(E, F, G, H, A, B, C, D, W[ 4], 0x3956c25b);
    P(D, E, F, G, H, A, B, C, W[ 5], 0x59f111f1);
    P(C, D, E, F, G, H, A, B, W[ 6], 0x923f82a4);
    P(B, C, D, E, F, G, H, A, W[ 7], 0xab1c5ed5);
    P(A, B, C, D, E, F, G, H, W[ 8], 0xd807aa98);
    P(H, A, B, C, D, E, F, G, W[ 9], 0x12835b01);
    P(G, H, A, B, C, D, E, F, W[10], 0x243185be);
    P(F, G, H, A, B, C, D, E, W[11], 0x550c7dc3);
    P(E, F, G, H, A, B, C, D, W[12], 0x72be5d74);
    P(D, E, F, G, H, A, B, C, W[13], 0x80deb1fe);
    P(C, D, E, F, G, H, A, B, W[14], 0x9bdc06a7);
    P(B, C, D, E, F, G, H, A, W[15], 0xc19bf174);
    P(A, B, C, D, E, F, G, H, R( 0), 0xe49b69c1);
    P(H, A, B, C, D, E, F, G, R( 1), 0xefbe4786);
    P(G, H, A, B, C, D, E, F, R( 2), 0x0fc19dc6);
    P(F, G, H, A, B, C, D, E, R( 3), 0x240ca1cc);
    P(E, F, G, H, A, B, C, D, R( 4), 0x2de92c6f);
    P(D, E, F, G, H, A, B, C, R( 5), 0x4a7484aa);
    P(C, D, E, F, G, H, A, B, R( 6), 0x5cb0a9dc);
    P(B, C, D, E, F, G, H, A, R( 7), 0x76f988da);
    P(A, B, C, D, E, F, G, H, R( 8), 0x983e5152);
    P(H, A, B, C, D, E, F, G, R( 9), 0xa831c66d);
    P(G, H, A, B, C, D, E, F, R(10), 0xb00327c8);
    P(F, G, H, A, B, C, D, E, R(11), 0xbf597fc7);
    P(E, F, G, H, A, B, C, D, R(12), 0xc6e00bf3);
    P(D, E, F, G, H, A, B, C, R(13), 0xd5a79147);
    P(C, D, E, F, G, H, A, B, R(14), 0x06ca6351);
    P(B, C, D, E, F, G, H, A, R(15), 0x14292967);
    P(A, B, C, D, E, F, G, H, R( 0), 0x27b70a85);
    P(H, A, B, C, D, E, F, G, R( 1), 0x2e1b2138);
    P(G, H, A, B, C, D, E, F, R( 2), 0x4d2c6dfc);
    P(F, G, H, A, B, C, D, E, R( 3), 0x53380d13);
    P(E, F, G, H, A, B, C, D, R( 4), 0x650a7354);
    P(D, E, F, G, H, A, B, C, R( 5), 0x766a0abb);
    P(C, D, E, F, G, H, A, B, R( 6), 0x81c2c92e);
    P(B, C, D, E, F, G, H, A, R( 7), 0x92722c85);
    P(A, B, C, D, E, F, G, H, R( 8), 0xa2bfe8a1);
    P(H, A, B, C, D, E, F, G, R( 9), 0xa81a664b);
    P(G, H, A, B, C, D, E, F, R(10), 0xc24b8b70);
    P(F, G, H, A, B, C, D, E, R(11), 0xc76c51a3);
    P(E, F, G, H, A, B, C, D, R(12), 0xd192e819);
    P(D, E, F, G, H, A, B, C, R(13), 0xd6990624);
    P(C, D, E, F, G, H, A, B, R(14), 0xf40e3585);
    P(B, C, D, E, F, G, H, A, R(15), 0x106aa070);
    P(A, B, C, D, E, F, G, H, R( 0), 0x19a4c116);
    P(H, A, B, C, D, E, F, G, R( 1), 0x1e376c08);
    P(G, H, A, B, C, D, E, F, R( 2), 0x2748774c);
    P(F, G, H, A, B, C, D, E, R( 3), 0x34b0bcb5);
    P(E, F, G, H, A, B, C, D, R( 4), 0x391c0cb3);
    P(D, E, F, G, H, A, B, C, R( 5), 0x4ed8aa4a);
    P(C, D, E, F, G, H, A, B, R( 6), 0x5b9cca4f);
    P(B, C, D, E, F, G, H, A, R( 7), 0x682e6ff3);
    P(A, B, C, D, E, F, G, H, R( 8), 0x748f82ee);
    P(H, A, B, C, D, E, F, G, R( 9), 0x78a5636f);
    P(G, H, A, B, C, D, E, F, R(10), 0x84c87814);
    P(F, G, H, A, B, C, D, E, R(11), 0x8cc70208);
    P(E, F, G, H, A, B, C, D, R(12), 0x90befffa);
    P(D, E, F, G, H, A, B, C, R(13), 0xa4506ceb);
    P(C, D, E, F, G, H, A, B, R(14), 0xbef9a3f7);
    P(B, C, D, E, F, G, H, A, R(15), 0xc67178f2);

    digest[0] = A + 0x6a09e667; digest[1] = B + 0xbb67ae85;
    digest[2] = C + 0x3c6ef372; digest[3] = D + 0xa54ff53a;
    digest[4] = E + 0x510e527f; digest[5] = F + 0x9b05688c;
    digest[6] = G + 0x1f83d9ab; digest[7] = H + 0x5be0cd19;
  }
}
