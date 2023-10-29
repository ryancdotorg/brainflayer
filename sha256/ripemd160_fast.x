#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <endian.h>

#define RotL(X, I) (((X) << (I)) | ((X) >> (32 - (I))))

#define RoundF1(A, B, C, D, E, X, K, R) {\
    A = RotL(A + (B ^ C ^ D) + X + K, R) + E; \
    C = RotL(C, 10); }

#define RoundF2(A, B, C, D, E, X, K, R) {\
    A = RotL(A + (((C ^ D) & B) ^ D) + X + K, R) + E; \
    C = RotL(C, 10); }

#define RoundF3(A, B, C, D, E, X, K, R) {\
    A = RotL(A + ((~C | B) ^ D) + X + K, R) + E; \
    C = RotL(C, 10); }

#define RoundF4(A, B, C, D, E, X, K, R) {\
    A = RotL(A + (((B ^ C) & D) ^ C) + X + K, R) + E; \
    C = RotL(C, 10); }

#define RoundF5(A, B, C, D, E, X, K, R) {\
    A = RotL(A + ((~D | C) ^ B) + X + K, R) + E; \
    C = RotL(C, 10); }

#define RMD11(A, B, C, D, E, X, R) RoundF1(A, B, C, D, E, X, 0x00000000, R)
#define RMD21(A, B, C, D, E, X, R) RoundF2(A, B, C, D, E, X, 0x5A827999, R)
#define RMD31(A, B, C, D, E, X, R) RoundF3(A, B, C, D, E, X, 0x6ED9EBA1, R)
#define RMD41(A, B, C, D, E, X, R) RoundF4(A, B, C, D, E, X, 0x8F1BBCDC, R)
#define RMD51(A, B, C, D, E, X, R) RoundF5(A, B, C, D, E, X, 0xA953FD4E, R)

#define RMD12(A, B, C, D, E, X, R) RoundF5(A, B, C, D, E, X, 0x50A28BE6, R)
#define RMD22(A, B, C, D, E, X, R) RoundF4(A, B, C, D, E, X, 0x5C4DD124, R)
#define RMD32(A, B, C, D, E, X, R) RoundF3(A, B, C, D, E, X, 0x6D703EF3, R)
#define RMD42(A, B, C, D, E, X, R) RoundF2(A, B, C, D, E, X, 0x7A6D76E9, R)
#define RMD52(A, B, C, D, E, X, R) RoundF1(A, B, C, D, E, X, 0x00000000, R)

#define RMD160_LOAD_STATE_EARLY
//#define RMD160_HARDCODE_PADDING

#ifndef RMD160_FN_NAME
#define RMD160_FN_NAME ripemd160_fast
#endif

#pragma GCC push_options
#pragma GCC optimize ("-fno-schedule-insns")
#pragma GCC optimize ("-fno-schedule-insns2")
void RMD160_FN_NAME(uint32_t *s, const char *data) {
#ifdef RMD160_LOAD_STATE_EARLY
    s[0] = 0x67452301; s[1] = 0xEFCDAB89; s[2] = 0x98BADCFE; s[3] = 0x10325476; s[4] = 0xC3D2E1F0;
    //uint32_t a1 = s[0], b1 = s[1], c1 = s[2], d1 = s[3], e1 = s[4];
#else
    //uint32_t a1 = 0x67452301, b1 = 0xEFCDAB89, c1 = 0x98BADCFE, d1 = 0x10325476, e1 = 0xC3D2E1F0;
#endif
    uint32_t z[5];
    z[0] = s[0], z[1] = s[1], z[2] = s[2], z[3] = s[3], z[4] = s[4];

    const uint32_t *in = (uint32_t*)data;
    uint32_t w[16];
    w[0] = htole32(in[ 0]),  w[1] = htole32(in[ 1]),  w[2] = htole32(in[ 2]),  w[3] = htole32(in[ 3]);
    w[4] = htole32(in[ 4]),  w[5] = htole32(in[ 5]),  w[6] = htole32(in[ 6]),  w[7] = htole32(in[ 7]);
#ifdef RMD160_HARDCODE_PADDING
    w[8] = htole32(128), w[9] = 0, w[10] = 0, w[11] = 0, w[12] = 0, w[13] = 0, w[14] = htole32(256), w[15] = 0;
#else
    w[8] = htole32(in[ 8]),  w[9] = htole32(in[ 9]), w[10] = htole32(in[10]), w[11] = htole32(in[11]);
    w[12] = htole32(in[12]), w[13] = htole32(in[13]), w[14] = htole32(in[14]), w[15] = htole32(in[15]);
#endif

    RMD11(s[0], s[1], s[2], s[3], s[4], w[0], 11);
    RMD12(z[0], z[1], z[2], z[3], z[4], w[5], 8);
    RMD11(s[4], s[0], s[1], s[2], s[3], w[1], 14);
    RMD12(z[4], z[0], z[1], z[2], z[3], w[14], 9);
    RMD11(s[3], s[4], s[0], s[1], s[2], w[2], 15);
    RMD12(z[3], z[4], z[0], z[1], z[2], w[7], 9);
    RMD11(s[2], s[3], s[4], s[0], s[1], w[3], 12);
    RMD12(z[2], z[3], z[4], z[0], z[1], w[0], 11);
    RMD11(s[1], s[2], s[3], s[4], s[0], w[4], 5);
    RMD12(z[1], z[2], z[3], z[4], z[0], w[9], 13);
    RMD11(s[0], s[1], s[2], s[3], s[4], w[5], 8);
    RMD12(z[0], z[1], z[2], z[3], z[4], w[2], 15);
    RMD11(s[4], s[0], s[1], s[2], s[3], w[6], 7);
    RMD12(z[4], z[0], z[1], z[2], z[3], w[11], 15);
    RMD11(s[3], s[4], s[0], s[1], s[2], w[7], 9);
    RMD12(z[3], z[4], z[0], z[1], z[2], w[4], 5);
    RMD11(s[2], s[3], s[4], s[0], s[1], w[8], 11);
    RMD12(z[2], z[3], z[4], z[0], z[1], w[13], 7);
    RMD11(s[1], s[2], s[3], s[4], s[0], w[9], 13);
    RMD12(z[1], z[2], z[3], z[4], z[0], w[6], 7);
    RMD11(s[0], s[1], s[2], s[3], s[4], w[10], 14);
    RMD12(z[0], z[1], z[2], z[3], z[4], w[15], 8);
    RMD11(s[4], s[0], s[1], s[2], s[3], w[11], 15);
    RMD12(z[4], z[0], z[1], z[2], z[3], w[8], 11);
    RMD11(s[3], s[4], s[0], s[1], s[2], w[12], 6);
    RMD12(z[3], z[4], z[0], z[1], z[2], w[1], 14);
    RMD11(s[2], s[3], s[4], s[0], s[1], w[13], 7);
    RMD12(z[2], z[3], z[4], z[0], z[1], w[10], 14);
    RMD11(s[1], s[2], s[3], s[4], s[0], w[14], 9);
    RMD12(z[1], z[2], z[3], z[4], z[0], w[3], 12);
    RMD11(s[0], s[1], s[2], s[3], s[4], w[15], 8);
    RMD12(z[0], z[1], z[2], z[3], z[4], w[12], 6);

    RMD21(s[4], s[0], s[1], s[2], s[3], w[7], 7);
    RMD22(z[4], z[0], z[1], z[2], z[3], w[6], 9);
    RMD21(s[3], s[4], s[0], s[1], s[2], w[4], 6);
    RMD22(z[3], z[4], z[0], z[1], z[2], w[11], 13);
    RMD21(s[2], s[3], s[4], s[0], s[1], w[13], 8);
    RMD22(z[2], z[3], z[4], z[0], z[1], w[3], 15);
    RMD21(s[1], s[2], s[3], s[4], s[0], w[1], 13);
    RMD22(z[1], z[2], z[3], z[4], z[0], w[7], 7);
    RMD21(s[0], s[1], s[2], s[3], s[4], w[10], 11);
    RMD22(z[0], z[1], z[2], z[3], z[4], w[0], 12);
    RMD21(s[4], s[0], s[1], s[2], s[3], w[6], 9);
    RMD22(z[4], z[0], z[1], z[2], z[3], w[13], 8);
    RMD21(s[3], s[4], s[0], s[1], s[2], w[15], 7);
    RMD22(z[3], z[4], z[0], z[1], z[2], w[5], 9);
    RMD21(s[2], s[3], s[4], s[0], s[1], w[3], 15);
    RMD22(z[2], z[3], z[4], z[0], z[1], w[10], 11);
    RMD21(s[1], s[2], s[3], s[4], s[0], w[12], 7);
    RMD22(z[1], z[2], z[3], z[4], z[0], w[14], 7);
    RMD21(s[0], s[1], s[2], s[3], s[4], w[0], 12);
    RMD22(z[0], z[1], z[2], z[3], z[4], w[15], 7);
    RMD21(s[4], s[0], s[1], s[2], s[3], w[9], 15);
    RMD22(z[4], z[0], z[1], z[2], z[3], w[8], 12);
    RMD21(s[3], s[4], s[0], s[1], s[2], w[5], 9);
    RMD22(z[3], z[4], z[0], z[1], z[2], w[12], 7);
    RMD21(s[2], s[3], s[4], s[0], s[1], w[2], 11);
    RMD22(z[2], z[3], z[4], z[0], z[1], w[4], 6);
    RMD21(s[1], s[2], s[3], s[4], s[0], w[14], 7);
    RMD22(z[1], z[2], z[3], z[4], z[0], w[9], 15);
    RMD21(s[0], s[1], s[2], s[3], s[4], w[11], 13);
    RMD22(z[0], z[1], z[2], z[3], z[4], w[1], 13);
    RMD21(s[4], s[0], s[1], s[2], s[3], w[8], 12);
    RMD22(z[4], z[0], z[1], z[2], z[3], w[2], 11);

    RMD31(s[3], s[4], s[0], s[1], s[2], w[3], 11);
    RMD32(z[3], z[4], z[0], z[1], z[2], w[15], 9);
    RMD31(s[2], s[3], s[4], s[0], s[1], w[10], 13);
    RMD32(z[2], z[3], z[4], z[0], z[1], w[5], 7);
    RMD31(s[1], s[2], s[3], s[4], s[0], w[14], 6);
    RMD32(z[1], z[2], z[3], z[4], z[0], w[1], 15);
    RMD31(s[0], s[1], s[2], s[3], s[4], w[4], 7);
    RMD32(z[0], z[1], z[2], z[3], z[4], w[3], 11);
    RMD31(s[4], s[0], s[1], s[2], s[3], w[9], 14);
    RMD32(z[4], z[0], z[1], z[2], z[3], w[7], 8);
    RMD31(s[3], s[4], s[0], s[1], s[2], w[15], 9);
    RMD32(z[3], z[4], z[0], z[1], z[2], w[14], 6);
    RMD31(s[2], s[3], s[4], s[0], s[1], w[8], 13);
    RMD32(z[2], z[3], z[4], z[0], z[1], w[6], 6);
    RMD31(s[1], s[2], s[3], s[4], s[0], w[1], 15);
    RMD32(z[1], z[2], z[3], z[4], z[0], w[9], 14);
    RMD31(s[0], s[1], s[2], s[3], s[4], w[2], 14);
    RMD32(z[0], z[1], z[2], z[3], z[4], w[11], 12);
    RMD31(s[4], s[0], s[1], s[2], s[3], w[7], 8);
    RMD32(z[4], z[0], z[1], z[2], z[3], w[8], 13);
    RMD31(s[3], s[4], s[0], s[1], s[2], w[0], 13);
    RMD32(z[3], z[4], z[0], z[1], z[2], w[12], 5);
    RMD31(s[2], s[3], s[4], s[0], s[1], w[6], 6);
    RMD32(z[2], z[3], z[4], z[0], z[1], w[2], 14);
    RMD31(s[1], s[2], s[3], s[4], s[0], w[13], 5);
    RMD32(z[1], z[2], z[3], z[4], z[0], w[10], 13);
    RMD31(s[0], s[1], s[2], s[3], s[4], w[11], 12);
    RMD32(z[0], z[1], z[2], z[3], z[4], w[0], 13);
    RMD31(s[4], s[0], s[1], s[2], s[3], w[5], 7);
    RMD32(z[4], z[0], z[1], z[2], z[3], w[4], 7);
    RMD31(s[3], s[4], s[0], s[1], s[2], w[12], 5);
    RMD32(z[3], z[4], z[0], z[1], z[2], w[13], 5);

    RMD41(s[2], s[3], s[4], s[0], s[1], w[1], 11);
    RMD42(z[2], z[3], z[4], z[0], z[1], w[8], 15);
    RMD41(s[1], s[2], s[3], s[4], s[0], w[9], 12);
    RMD42(z[1], z[2], z[3], z[4], z[0], w[6], 5);
    RMD41(s[0], s[1], s[2], s[3], s[4], w[11], 14);
    RMD42(z[0], z[1], z[2], z[3], z[4], w[4], 8);
    RMD41(s[4], s[0], s[1], s[2], s[3], w[10], 15);
    RMD42(z[4], z[0], z[1], z[2], z[3], w[1], 11);
    RMD41(s[3], s[4], s[0], s[1], s[2], w[0], 14);
    RMD42(z[3], z[4], z[0], z[1], z[2], w[3], 14);
    RMD41(s[2], s[3], s[4], s[0], s[1], w[8], 15);
    RMD42(z[2], z[3], z[4], z[0], z[1], w[11], 14);
    RMD41(s[1], s[2], s[3], s[4], s[0], w[12], 9);
    RMD42(z[1], z[2], z[3], z[4], z[0], w[15], 6);
    RMD41(s[0], s[1], s[2], s[3], s[4], w[4], 8);
    RMD42(z[0], z[1], z[2], z[3], z[4], w[0], 14);
    RMD41(s[4], s[0], s[1], s[2], s[3], w[13], 9);
    RMD42(z[4], z[0], z[1], z[2], z[3], w[5], 6);
    RMD41(s[3], s[4], s[0], s[1], s[2], w[3], 14);
    RMD42(z[3], z[4], z[0], z[1], z[2], w[12], 9);
    RMD41(s[2], s[3], s[4], s[0], s[1], w[7], 5);
    RMD42(z[2], z[3], z[4], z[0], z[1], w[2], 12);
    RMD41(s[1], s[2], s[3], s[4], s[0], w[15], 6);
    RMD42(z[1], z[2], z[3], z[4], z[0], w[13], 9);
    RMD41(s[0], s[1], s[2], s[3], s[4], w[14], 8);
    RMD42(z[0], z[1], z[2], z[3], z[4], w[9], 12);
    RMD41(s[4], s[0], s[1], s[2], s[3], w[5], 6);
    RMD42(z[4], z[0], z[1], z[2], z[3], w[7], 5);
    RMD41(s[3], s[4], s[0], s[1], s[2], w[6], 5);
    RMD42(z[3], z[4], z[0], z[1], z[2], w[10], 15);
    RMD41(s[2], s[3], s[4], s[0], s[1], w[2], 12);
    RMD42(z[2], z[3], z[4], z[0], z[1], w[14], 8);

    RMD51(s[1], s[2], s[3], s[4], s[0], w[4], 9);
    RMD52(z[1], z[2], z[3], z[4], z[0], w[12], 8);
    RMD51(s[0], s[1], s[2], s[3], s[4], w[0], 15);
    RMD52(z[0], z[1], z[2], z[3], z[4], w[15], 5);
    RMD51(s[4], s[0], s[1], s[2], s[3], w[5], 5);
    RMD52(z[4], z[0], z[1], z[2], z[3], w[10], 12);
    RMD51(s[3], s[4], s[0], s[1], s[2], w[9], 11);
    RMD52(z[3], z[4], z[0], z[1], z[2], w[4], 9);
    RMD51(s[2], s[3], s[4], s[0], s[1], w[7], 6);
    RMD52(z[2], z[3], z[4], z[0], z[1], w[1], 12);
    RMD51(s[1], s[2], s[3], s[4], s[0], w[12], 8);
    RMD52(z[1], z[2], z[3], z[4], z[0], w[5], 5);
    RMD51(s[0], s[1], s[2], s[3], s[4], w[2], 13);
    RMD52(z[0], z[1], z[2], z[3], z[4], w[8], 14);
    RMD51(s[4], s[0], s[1], s[2], s[3], w[10], 12);
    RMD52(z[4], z[0], z[1], z[2], z[3], w[7], 6);
    RMD51(s[3], s[4], s[0], s[1], s[2], w[14], 5);
    RMD52(z[3], z[4], z[0], z[1], z[2], w[6], 8);
    RMD51(s[2], s[3], s[4], s[0], s[1], w[1], 12);
    RMD52(z[2], z[3], z[4], z[0], z[1], w[2], 13);
    RMD51(s[1], s[2], s[3], s[4], s[0], w[3], 13);
    RMD52(z[1], z[2], z[3], z[4], z[0], w[13], 6);
    RMD51(s[0], s[1], s[2], s[3], s[4], w[8], 14);
    RMD52(z[0], z[1], z[2], z[3], z[4], w[14], 5);
    RMD51(s[4], s[0], s[1], s[2], s[3], w[11], 11);
    RMD52(z[4], z[0], z[1], z[2], z[3], w[0], 15);
    RMD51(s[3], s[4], s[0], s[1], s[2], w[6], 8);
    RMD52(z[3], z[4], z[0], z[1], z[2], w[3], 13);
    RMD51(s[2], s[3], s[4], s[0], s[1], w[15], 5);
    RMD52(z[2], z[3], z[4], z[0], z[1], w[9], 11);
    RMD51(s[1], s[2], s[3], s[4], s[0], w[13], 6);
    RMD52(z[1], z[2], z[3], z[4], z[0], w[11], 11);

#ifdef ZRMD160_LOAD_STATE_EARLY
    uint32_t t = s[0];
    s[0] = s[1] + s[2] + z[3];
    s[1] = s[2] + s[3] + z[4];
    s[2] = s[3] + s[4] + z[0];
    s[3] = s[4] + s[0] + z[1];
    s[4] = t + s[1] + z[2];
#else
    s[0] = 0xEFCDAB89 + s[2] + z[3];
    s[1] = 0x98BADCFE + s[3] + z[4];
    s[2] = 0x10325476 + s[4] + z[0];
    s[3] = 0xC3D2E1F0 + s[0] + z[1];
    s[4] = 0x67452301 + s[1] + z[2];
#endif
}
#pragma GCC pop_options

#if RMD160_FN_NAME == Transform
int main2() {
    unsigned char buf[] = {
        0x30, 0x31, 0x32, 0x33,  0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x41, 0x42,  0x43, 0x44, 0x45, 0x46,
        0x30, 0x31, 0x32, 0x33,  0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x41, 0x42,  0x43, 0x44, 0x45, 0x46,

        0x80, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00
    };

    uint32_t hash[5];

    RMD160_FN_NAME(hash, buf);

    for (int i = 0; i < 5; ++i) {
        hash[i] = htobe32(hash[i]);
        printf("%08x", hash[i]);
    }
    printf("\n");

    return 0;
}
#endif

#undef RMD160_FN_NAME
#undef RotL
#undef RoundF1
#undef RoundF2
#undef RoundF3
#undef RoundF4
#undef RoundF5
#undef RMD11
#undef RMD21
#undef RMD31
#undef RMD41
#undef RMD51
#undef RMD12
#undef RMD22
#undef RMD32
#undef RMD42
#undef RMD52
