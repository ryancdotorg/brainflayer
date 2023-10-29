#include <string.h>
#include <stdint.h>
#include <endian.h>

static uint32_t u32t;

#define asmRf1(a, b, c, d, e, x, K, R) \
asm volatile (\
	"movl %3, %2\n\t" \
	"xorl %1, %2\n\t" \
	"xorl %4, %2\n\t" \
	\
	"addl %2, %0\n\t" \
	"leal " #K "(%5, %0), %0\n\t" \
	"roll %7, %0\n\t" \
	"addl %5, %0\n\t" \
	"roll $10, %1\n\t" \
	: "+r" (a), "+r" (c), "=&r" (u32t)\
	: "r" (b), "r" (d), "r" (e), "r" (x), "I" (R) \
	: "cc" \
);

#define asmRf2(a, b, c, d, e, x, K, R) \
asm volatile (\
	"movl %1, %2\n\t" \
	"xorl %4, %2\n\t" \
	"andl %3, %2\n\t" \
	"xorl %4, %2\n\t" \
	\
	"addl %2, %0\n\t" \
	"leal " #K "(%5, %0), %0\n\t" \
	"roll %7, %0\n\t" \
	"addl %5, %0\n\t" \
	"roll $10, %1\n\t" \
	: "+r" (a), "+r" (c), "=&r" (u32t)\
	: "r" (b), "r" (d), "r" (e), "r" (x), "I" (R) \
	: "cc" \
);

#define asmRf3(a, b, c, d, e, x, K, R) \
asm volatile (\
	"movl %1, %2\n\t" \
	"notl %2\n\t"     \
	"orl  %3, %2\n\t" \
	"xorl %4, %2\n\t" \
	\
	"addl %2, %0\n\t" \
	"leal " #K "(%5, %0), %0\n\t" \
	"roll %7, %0\n\t" \
	"addl %5, %0\n\t" \
	"roll $10, %1\n\t" \
	: "+r" (a), "+r" (c), "=&r" (u32t)\
	: "r" (b), "r" (d), "r" (e), "r" (x), "I" (R) \
	: "cc" \
);

#define asmRf4(a, b, c, d, e, x, K, R) \
asm volatile (\
	"movl %3, %2\n\t" \
	"xorl %1, %2\n\t" \
	"andl %4, %2\n\t" \
	"xorl %1, %2\n\t" \
	\
	"addl %2, %0\n\t" \
	"leal " #K "(%5, %0), %0\n\t" \
	"roll %7, %0\n\t" \
	"addl %5, %0\n\t" \
	"roll $10, %1\n\t" \
	: "+r" (a), "+r" (c), "=&r" (u32t)\
	: "r" (b), "r" (d), "r" (e), "r" (x), "I" (R) \
	: "cc" \
);

#define asmRf5(a, b, c, d, e, x, K, R) \
asm volatile (\
	"movl %4, %2\n\t" \
	"notl %2\n\t"     \
	"orl  %1, %2\n\t" \
	"xorl %3, %2\n\t" \
	\
	"addl %2, %0\n\t" \
	"leal " #K "(%5, %0), %0\n\t" \
	"roll %7, %0\n\t" \
	"addl %5, %0\n\t" \
	"roll $10, %1\n\t" \
	: "+r" (a), "+r" (c), "=&r" (u32t)\
	: "r" (b), "r" (d), "r" (e), "r" (x), "I" (R) \
	: "cc" \
);

// f1: x ^ y ^ z         ; mov B, T; xor C, T; xor D, T
// f2: ((y ^ z) & x) ^ z ; mov C, T; xor D, T; and B, T; xor D, T
// f3: (~y | x) ^ z      ; mov C, T; not T   ; or  B, T; xor D, T
// f4: ((x ^ y) & z) ^ y ; mov B, T; xor C, T; and D, T; xor C, T
// f5: (~z | y) ^ x      ; mov D, T; not T   ; or  C, T; xor B, T

#define RMD11(A, B, C, D, E, X, R) asmRf1(A, B, C, D, E, X, 0x00000000, R)
#define RMD21(A, B, C, D, E, X, R) asmRf2(A, B, C, D, E, X, 0x5A827999, R)
#define RMD31(A, B, C, D, E, X, R) asmRf3(A, B, C, D, E, X, 0x6ED9EBA1, R)
#define RMD41(A, B, C, D, E, X, R) asmRf4(A, B, C, D, E, X, 0x8F1BBCDC, R)
#define RMD51(A, B, C, D, E, X, R) asmRf5(A, B, C, D, E, X, 0xA953FD4E, R)

#define RMD12(A, B, C, D, E, X, R) asmRf5(A, B, C, D, E, X, 0x50A28BE6, R)
#define RMD22(A, B, C, D, E, X, R) asmRf4(A, B, C, D, E, X, 0x5C4DD124, R)
#define RMD32(A, B, C, D, E, X, R) asmRf3(A, B, C, D, E, X, 0x6D703EF3, R)
#define RMD42(A, B, C, D, E, X, R) asmRf2(A, B, C, D, E, X, 0x7A6D76E9, R)
#define RMD52(A, B, C, D, E, X, R) asmRf1(A, B, C, D, E, X, 0x00000000, R)


// compute the RIPEMD-160 hash of a 256 bit input in a single call
void ripemd160_asm(uint32_t* s, const unsigned char* data) {
	// initalize hash state
	uint32_t a1 = 0x67452301;
	uint32_t b1 = 0xEFCDAB89;
	uint32_t c1 = 0x98BADCFE;
	uint32_t d1 = 0x10325476;
	uint32_t e1 = 0xC3D2E1F0;
	uint32_t a2 = a1, b2 = b1, c2 = c1, d2 = d1, e2 = e1;

	// read in 256 bits of data
	const uint32_t *input=(uint32_t *)data;
	uint32_t  w0 = htole32(input[ 0]),  w1 = htole32(input[ 1]),  w2 = htole32(input[ 2]),  w3 = htole32(input[ 3]);
	uint32_t  w4 = htole32(input[ 4]),  w5 = htole32(input[ 5]),  w6 = htole32(input[ 6]),  w7 = htole32(input[ 7]);
	// pad for 256 bits of data
	//uint32_t w8 = 128, w9 = 0, w10 = 0, w11 = 0;
	//uint32_t w12 = 0, w13 = 0, w14 = 256, w15 = 0;
	uint32_t  w8 = htole32(input[ 8]),  w9 = htole32(input[ 9]), w10 = htole32(input[10]), w11 = htole32(input[11]);
	uint32_t w12 = htole32(input[12]), w13 = htole32(input[13]), w14 = htole32(input[14]), w15 = htole32(input[15]);

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

	s[0] = 0xEFCDAB89 + c1 + d2;
	s[1] = 0x98BADCFE + d1 + e2;
	s[2] = 0x10325476 + e1 + a2;
	s[3] = 0xC3D2E1F0 + a1 + b2;
	s[4] = 0x67452301 + b1 + c2;
}

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
