#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <endian.h>

#define RotL(X, I) (((X) << (I)) | ((X) >> (32 - (I))))

#define RoundF1(A, B, C, D, E, W, K, R) {\
    A = RotL(A + (B ^ C ^ D) + W + K, R) + E; \
    C = RotL(C, 10); }

#define RoundF2(A, B, C, D, E, W, K, R) {\
    A = RotL(A + (((C ^ D) & B) ^ D) + W + K, R) + E; \
    C = RotL(C, 10); }

#define RoundF3(A, B, C, D, E, W, K, R) {\
    A = RotL(A + ((~C | B) ^ D) + W + K, R) + E; \
    C = RotL(C, 10); }

#define RoundF4(A, B, C, D, E, W, K, R) {\
    A = RotL(A + (((B ^ C) & D) ^ C) + W + K, R) + E; \
    C = RotL(C, 10); }

#define RoundF5(A, B, C, D, E, W, K, R) {\
    A = RotL(A + ((~D | C) ^ B) + W + K, R) + E; \
    C = RotL(C, 10); }

#define RMD11(A, B, C, D, E, W, R) RoundF1(A, B, C, D, E, W, 0x00000000, R)
#define RMD21(A, B, C, D, E, W, R) RoundF2(A, B, C, D, E, W, 0x5A827999, R)
#define RMD31(A, B, C, D, E, W, R) RoundF3(A, B, C, D, E, W, 0x6ED9EBA1, R)
#define RMD41(A, B, C, D, E, W, R) RoundF4(A, B, C, D, E, W, 0x8F1BBCDC, R)
#define RMD51(A, B, C, D, E, W, R) RoundF5(A, B, C, D, E, W, 0xA953FD4E, R)

#define RMD12(A, B, C, D, E, W, R) RoundF5(A, B, C, D, E, W, 0x50A28BE6, R)
#define RMD22(A, B, C, D, E, W, R) RoundF4(A, B, C, D, E, W, 0x5C4DD124, R)
#define RMD32(A, B, C, D, E, W, R) RoundF3(A, B, C, D, E, W, 0x6D703EF3, R)
#define RMD42(A, B, C, D, E, W, R) RoundF2(A, B, C, D, E, W, 0x7A6D76E9, R)
#define RMD52(A, B, C, D, E, W, R) RoundF1(A, B, C, D, E, W, 0x00000000, R)

//#define RMD160_LOAD_STATE_EARLY
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
    uint32_t a1 = s[0], b1 = s[1], c1 = s[2], d1 = s[3], e1 = s[4];
#else
    uint32_t a1 = 0x67452301, b1 = 0xEFCDAB89, c1 = 0x98BADCFE, d1 = 0x10325476, e1 = 0xC3D2E1F0;
#endif
    uint32_t a2 = a1, b2 = b1, c2 = c1, d2 = d1, e2 = e1;

    const uint32_t *in = (uint32_t*)data;
    uint32_t  w0 = htole32(in[ 0]),  w1 = htole32(in[ 1]),  w2 = htole32(in[ 2]),  w3 = htole32(in[ 3]);
    uint32_t  w4 = htole32(in[ 4]),  w5 = htole32(in[ 5]),  w6 = htole32(in[ 6]),  w7 = htole32(in[ 7]);
#ifdef RMD160_HARDCODE_PADDING
    uint32_t w8 = htole32(128), w9 = 0, w10 = 0, w11 = 0, w12 = 0, w13 = 0, w14 = htole32(256), w15 = 0;
#else
    uint32_t  w8 = htole32(in[ 8]),  w9 = htole32(in[ 9]), w10 = htole32(in[10]), w11 = htole32(in[11]);
    uint32_t w12 = htole32(in[12]), w13 = htole32(in[13]), w14 = htole32(in[14]), w15 = htole32(in[15]);
#endif

    RMD11(a1, b1, c1, d1, e1, w0, 11);
    RMD12(a2, b2, c2, d2, e2, w5, 8);
    RMD11(e1, a1, b1, c1, d1, w1, 14);
    RMD12(e2, a2, b2, c2, d2, w14, 9);
    RMD11(d1, e1, a1, b1, c1, w2, 15);
    RMD12(d2, e2, a2, b2, c2, w7, 9);
    RMD11(c1, d1, e1, a1, b1, w3, 12);
    RMD12(c2, d2, e2, a2, b2, w0, 11);
    RMD11(b1, c1, d1, e1, a1, w4, 5);
    RMD12(b2, c2, d2, e2, a2, w9, 13);
    RMD11(a1, b1, c1, d1, e1, w5, 8);
    RMD12(a2, b2, c2, d2, e2, w2, 15);
    RMD11(e1, a1, b1, c1, d1, w6, 7);
    RMD12(e2, a2, b2, c2, d2, w11, 15);
    RMD11(d1, e1, a1, b1, c1, w7, 9);
    RMD12(d2, e2, a2, b2, c2, w4, 5);
    RMD11(c1, d1, e1, a1, b1, w8, 11);
    RMD12(c2, d2, e2, a2, b2, w13, 7);
    RMD11(b1, c1, d1, e1, a1, w9, 13);
    RMD12(b2, c2, d2, e2, a2, w6, 7);
    RMD11(a1, b1, c1, d1, e1, w10, 14);
    RMD12(a2, b2, c2, d2, e2, w15, 8);
    RMD11(e1, a1, b1, c1, d1, w11, 15);
    RMD12(e2, a2, b2, c2, d2, w8, 11);
    RMD11(d1, e1, a1, b1, c1, w12, 6);
    RMD12(d2, e2, a2, b2, c2, w1, 14);
    RMD11(c1, d1, e1, a1, b1, w13, 7);
    RMD12(c2, d2, e2, a2, b2, w10, 14);
    RMD11(b1, c1, d1, e1, a1, w14, 9);
    RMD12(b2, c2, d2, e2, a2, w3, 12);
    RMD11(a1, b1, c1, d1, e1, w15, 8);
    RMD12(a2, b2, c2, d2, e2, w12, 6);

    RMD21(e1, a1, b1, c1, d1, w7, 7);
    RMD22(e2, a2, b2, c2, d2, w6, 9);
    RMD21(d1, e1, a1, b1, c1, w4, 6);
    RMD22(d2, e2, a2, b2, c2, w11, 13);
    RMD21(c1, d1, e1, a1, b1, w13, 8);
    RMD22(c2, d2, e2, a2, b2, w3, 15);
    RMD21(b1, c1, d1, e1, a1, w1, 13);
    RMD22(b2, c2, d2, e2, a2, w7, 7);
    RMD21(a1, b1, c1, d1, e1, w10, 11);
    RMD22(a2, b2, c2, d2, e2, w0, 12);
    RMD21(e1, a1, b1, c1, d1, w6, 9);
    RMD22(e2, a2, b2, c2, d2, w13, 8);
    RMD21(d1, e1, a1, b1, c1, w15, 7);
    RMD22(d2, e2, a2, b2, c2, w5, 9);
    RMD21(c1, d1, e1, a1, b1, w3, 15);
    RMD22(c2, d2, e2, a2, b2, w10, 11);
    RMD21(b1, c1, d1, e1, a1, w12, 7);
    RMD22(b2, c2, d2, e2, a2, w14, 7);
    RMD21(a1, b1, c1, d1, e1, w0, 12);
    RMD22(a2, b2, c2, d2, e2, w15, 7);
    RMD21(e1, a1, b1, c1, d1, w9, 15);
    RMD22(e2, a2, b2, c2, d2, w8, 12);
    RMD21(d1, e1, a1, b1, c1, w5, 9);
    RMD22(d2, e2, a2, b2, c2, w12, 7);
    RMD21(c1, d1, e1, a1, b1, w2, 11);
    RMD22(c2, d2, e2, a2, b2, w4, 6);
    RMD21(b1, c1, d1, e1, a1, w14, 7);
    RMD22(b2, c2, d2, e2, a2, w9, 15);
    RMD21(a1, b1, c1, d1, e1, w11, 13);
    RMD22(a2, b2, c2, d2, e2, w1, 13);
    RMD21(e1, a1, b1, c1, d1, w8, 12);
    RMD22(e2, a2, b2, c2, d2, w2, 11);

    RMD31(d1, e1, a1, b1, c1, w3, 11);
    RMD32(d2, e2, a2, b2, c2, w15, 9);
    RMD31(c1, d1, e1, a1, b1, w10, 13);
    RMD32(c2, d2, e2, a2, b2, w5, 7);
    RMD31(b1, c1, d1, e1, a1, w14, 6);
    RMD32(b2, c2, d2, e2, a2, w1, 15);
    RMD31(a1, b1, c1, d1, e1, w4, 7);
    RMD32(a2, b2, c2, d2, e2, w3, 11);
    RMD31(e1, a1, b1, c1, d1, w9, 14);
    RMD32(e2, a2, b2, c2, d2, w7, 8);
    RMD31(d1, e1, a1, b1, c1, w15, 9);
    RMD32(d2, e2, a2, b2, c2, w14, 6);
    RMD31(c1, d1, e1, a1, b1, w8, 13);
    RMD32(c2, d2, e2, a2, b2, w6, 6);
    RMD31(b1, c1, d1, e1, a1, w1, 15);
    RMD32(b2, c2, d2, e2, a2, w9, 14);
    RMD31(a1, b1, c1, d1, e1, w2, 14);
    RMD32(a2, b2, c2, d2, e2, w11, 12);
    RMD31(e1, a1, b1, c1, d1, w7, 8);
    RMD32(e2, a2, b2, c2, d2, w8, 13);
    RMD31(d1, e1, a1, b1, c1, w0, 13);
    RMD32(d2, e2, a2, b2, c2, w12, 5);
    RMD31(c1, d1, e1, a1, b1, w6, 6);
    RMD32(c2, d2, e2, a2, b2, w2, 14);
    RMD31(b1, c1, d1, e1, a1, w13, 5);
    RMD32(b2, c2, d2, e2, a2, w10, 13);
    RMD31(a1, b1, c1, d1, e1, w11, 12);
    RMD32(a2, b2, c2, d2, e2, w0, 13);
    RMD31(e1, a1, b1, c1, d1, w5, 7);
    RMD32(e2, a2, b2, c2, d2, w4, 7);
    RMD31(d1, e1, a1, b1, c1, w12, 5);
    RMD32(d2, e2, a2, b2, c2, w13, 5);

    RMD41(c1, d1, e1, a1, b1, w1, 11);
    RMD42(c2, d2, e2, a2, b2, w8, 15);
    RMD41(b1, c1, d1, e1, a1, w9, 12);
    RMD42(b2, c2, d2, e2, a2, w6, 5);
    RMD41(a1, b1, c1, d1, e1, w11, 14);
    RMD42(a2, b2, c2, d2, e2, w4, 8);
    RMD41(e1, a1, b1, c1, d1, w10, 15);
    RMD42(e2, a2, b2, c2, d2, w1, 11);
    RMD41(d1, e1, a1, b1, c1, w0, 14);
    RMD42(d2, e2, a2, b2, c2, w3, 14);
    RMD41(c1, d1, e1, a1, b1, w8, 15);
    RMD42(c2, d2, e2, a2, b2, w11, 14);
    RMD41(b1, c1, d1, e1, a1, w12, 9);
    RMD42(b2, c2, d2, e2, a2, w15, 6);
    RMD41(a1, b1, c1, d1, e1, w4, 8);
    RMD42(a2, b2, c2, d2, e2, w0, 14);
    RMD41(e1, a1, b1, c1, d1, w13, 9);
    RMD42(e2, a2, b2, c2, d2, w5, 6);
    RMD41(d1, e1, a1, b1, c1, w3, 14);
    RMD42(d2, e2, a2, b2, c2, w12, 9);
    RMD41(c1, d1, e1, a1, b1, w7, 5);
    RMD42(c2, d2, e2, a2, b2, w2, 12);
    RMD41(b1, c1, d1, e1, a1, w15, 6);
    RMD42(b2, c2, d2, e2, a2, w13, 9);
    RMD41(a1, b1, c1, d1, e1, w14, 8);
    RMD42(a2, b2, c2, d2, e2, w9, 12);
    RMD41(e1, a1, b1, c1, d1, w5, 6);
    RMD42(e2, a2, b2, c2, d2, w7, 5);
    RMD41(d1, e1, a1, b1, c1, w6, 5);
    RMD42(d2, e2, a2, b2, c2, w10, 15);
    RMD41(c1, d1, e1, a1, b1, w2, 12);
    RMD42(c2, d2, e2, a2, b2, w14, 8);

    RMD51(b1, c1, d1, e1, a1, w4, 9);
    RMD52(b2, c2, d2, e2, a2, w12, 8);
    RMD51(a1, b1, c1, d1, e1, w0, 15);
    RMD52(a2, b2, c2, d2, e2, w15, 5);
    RMD51(e1, a1, b1, c1, d1, w5, 5);
    RMD52(e2, a2, b2, c2, d2, w10, 12);
    RMD51(d1, e1, a1, b1, c1, w9, 11);
    RMD52(d2, e2, a2, b2, c2, w4, 9);
    RMD51(c1, d1, e1, a1, b1, w7, 6);
    RMD52(c2, d2, e2, a2, b2, w1, 12);
    RMD51(b1, c1, d1, e1, a1, w12, 8);
    RMD52(b2, c2, d2, e2, a2, w5, 5);
    RMD51(a1, b1, c1, d1, e1, w2, 13);
    RMD52(a2, b2, c2, d2, e2, w8, 14);
    RMD51(e1, a1, b1, c1, d1, w10, 12);
    RMD52(e2, a2, b2, c2, d2, w7, 6);
    RMD51(d1, e1, a1, b1, c1, w14, 5);
    RMD52(d2, e2, a2, b2, c2, w6, 8);
    RMD51(c1, d1, e1, a1, b1, w1, 12);
    RMD52(c2, d2, e2, a2, b2, w2, 13);
    RMD51(b1, c1, d1, e1, a1, w3, 13);
    RMD52(b2, c2, d2, e2, a2, w13, 6);
    RMD51(a1, b1, c1, d1, e1, w8, 14);
    RMD52(a2, b2, c2, d2, e2, w14, 5);
    RMD51(e1, a1, b1, c1, d1, w11, 11);
    RMD52(e2, a2, b2, c2, d2, w0, 15);
    RMD51(d1, e1, a1, b1, c1, w6, 8);
    RMD52(d2, e2, a2, b2, c2, w3, 13);
    RMD51(c1, d1, e1, a1, b1, w15, 5);
    RMD52(c2, d2, e2, a2, b2, w9, 11);
    RMD51(b1, c1, d1, e1, a1, w13, 6);
    RMD52(b2, c2, d2, e2, a2, w11, 11);

#ifdef RMD160_LOAD_STATE_EARLY
    uint32_t t = s[0];
    s[0] = s[1] + c1 + d2;
    s[1] = s[2] + d1 + e2;
    s[2] = s[3] + e1 + a2;
    s[3] = s[4] + a1 + b2;
    s[4] = t + b1 + c2;
#else
    s[0] = 0xEFCDAB89 + c1 + d2;
    s[1] = 0x98BADCFE + d1 + e2;
    s[2] = 0x10325476 + e1 + a2;
    s[3] = 0xC3D2E1F0 + a1 + b2;
    s[4] = 0x67452301 + b1 + c2;
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
