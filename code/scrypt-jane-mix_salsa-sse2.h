/* x86/64 gcc gets inline asm */
#if (!defined(SCRYPT_CHOOSE_COMPILETIME) && defined(COMPILER_GCC) && (defined(X86ASM_SSE2) || defined(X86_64ASM_SSE2))) || (defined(SYSTEM_SSE2) && !defined(SCRYPT_SALSA_INCLUDED))

#undef SCRYPT_MIX
#define SCRYPT_MIX "Salsa20/8 SSE2"

#undef SCRYPT_SALSA_INCLUDED
#define SCRYPT_SALSA_INCLUDED
#define SCRYPT_SALSA_SSE2

static void INLINE
salsa_core_sse2(uint32_t state[16]) {
	size_t rounds = 8;
	asm_gcc()
		a2(movdqa xmm0,[%1+0])
		a2(movdqa xmm1,[%1+16])
		a2(movdqa xmm2,[%1+32])
		a2(movdqa xmm3,[%1+48])
		a1(1: )
		a2(movdqa xmm4, xmm1)
		a2(paddd xmm4, xmm0)
		a2(movdqa xmm5, xmm4)
		a2(pslld xmm4, 7)
		a2(psrld xmm5, 25)
		a2(pxor xmm3, xmm4)
		a2(movdqa xmm4, xmm0)
		a2(pxor xmm3, xmm5)
		a2(paddd xmm4, xmm3)
		a2(movdqa xmm5, xmm4)
		a2(pslld xmm4, 9)
		a2(psrld xmm5, 23)
		a2(pxor xmm2, xmm4)
		a2(movdqa xmm4, xmm3)
		a2(pxor xmm2, xmm5)
		a3(pshufd xmm3, xmm3, 0x93)
		a2(paddd xmm4, xmm2)
		a2(movdqa xmm5, xmm4)
		a2(pslld xmm4, 13)
		a2(psrld xmm5, 19)
		a2(pxor xmm1, xmm4)
		a2(movdqa xmm4, xmm2)
		a2(pxor xmm1, xmm5)
		a3(pshufd xmm2, xmm2, 0x4e)
		a2(paddd xmm4, xmm1)
		a2(movdqa xmm5, xmm4)
		a2(pslld xmm4, 18)
		a2(psrld xmm5, 14)
		a2(pxor xmm0, xmm4)
		a2(movdqa xmm4, xmm3)
		a2(pxor xmm0, xmm5)
		a3(pshufd xmm1, xmm1, 0x39)
		a2(paddd xmm4, xmm0)
		a2(movdqa xmm5, xmm4)
		a2(pslld xmm4, 7)
		a2(psrld xmm5, 25)
		a2(pxor xmm1, xmm4)
		a2(movdqa xmm4, xmm0)
		a2(pxor xmm1, xmm5)
		a2(paddd xmm4, xmm1)
		a2(movdqa xmm5, xmm4)
		a2(pslld xmm4, 9)
		a2(psrld xmm5, 23)
		a2(pxor xmm2, xmm4)
		a2(movdqa xmm4, xmm1)
		a2(pxor xmm2, xmm5)
		a3(pshufd xmm1, xmm1, 0x93)
		a2(paddd xmm4, xmm2)
		a2(movdqa xmm5, xmm4)
		a2(pslld xmm4, 13)
		a2(psrld xmm5, 19)
		a2(pxor xmm3, xmm4)
		a2(movdqa xmm4, xmm2)
		a2(pxor xmm3, xmm5)
		a3(pshufd xmm2, xmm2, 0x4e)
		a2(paddd xmm4, xmm3)
		a2(sub %0, 2)
		a2(movdqa xmm5, xmm4)
		a2(pslld xmm4, 18)
		a2(psrld xmm5, 14)
		a2(pxor xmm0, xmm4)
		a3(pshufd xmm3, xmm3, 0x39)
		a2(pxor xmm0, xmm5)
		a1(ja 1b)
		a2(paddd xmm0,[%1+0])
		a2(paddd xmm1,[%1+16])
		a2(paddd xmm2,[%1+32])
		a2(paddd xmm3,[%1+48])
		a2(movdqa [%1+0],xmm0)
		a2(movdqa [%1+16],xmm1)
		a2(movdqa [%1+32],xmm2)
		a2(movdqa [%1+48],xmm3)
		asm_gcc_parms() : "+r"(rounds) : "r"(state) : "cc"
	asm_gcc_end()
}

static void
salsa_core_tangle_sse2(uint32_t *blocks, size_t count) {
	while (count--) {
		asm_gcc()
			a2(movdqa xmm0, [%0+0])
			a2(movdqa xmm3, [%0+16])
			a2(movdqa xmm2, [%0+32])
			a2(movdqa xmm1, [%0+48])
			a2(movdqa xmm4, xmm0)
			a2(pcmpeqw xmm5, xmm5)
			a2(psrlq xmm5, 32)
			a2(pxor xmm0, xmm3)
			a2(pand xmm0, xmm5)
			a2(pxor xmm0, xmm3)
			a2(pxor xmm3, xmm2)
			a2(pand xmm3, xmm5)
			a2(pxor xmm3, xmm2)
			a2(pxor xmm2, xmm1)
			a2(pand xmm2, xmm5)
			a2(pxor xmm2, xmm1)
			a2(pxor xmm1, xmm4)
			a2(pand xmm1, xmm5)
			a2(pxor xmm1, xmm4)
			a2(movdqa xmm4, xmm0)
			a2(movdqa xmm5, xmm3)
			a3(pshufd xmm2, xmm2, 0x4e)
			a3(pshufd xmm1, xmm1, 0x4e)
			a2(punpcklqdq xmm0, xmm2)
			a2(punpcklqdq xmm3, xmm1)
			a2(punpckhqdq xmm2, xmm4)
			a2(punpckhqdq xmm1, xmm5)
			a2(movdqa [%0+0], xmm0)
			a2(movdqa [%0+16], xmm1)
			a2(movdqa [%0+32], xmm2)
			a2(movdqa [%0+48], xmm3)
			asm_gcc_parms() :: "r"(blocks)
		asm_gcc_end()

		blocks += 16;
	}
}

static void
salsa_core_untangle_sse2(uint32_t *blocks, size_t count) {
	while (count--) {
		asm_gcc()
			a2(movdqa xmm0, [%0+0])
			a2(movdqa xmm1, [%0+16])
			a2(movdqa xmm2, [%0+32])
			a2(movdqa xmm3, [%0+48])
			a2(movdqa xmm4, xmm0)
			a2(pcmpeqw xmm5, xmm5)
			a2(psrlq xmm5, 32)
			a2(pxor xmm0, xmm1)
			a2(pand xmm0, xmm5)
			a2(pxor xmm0, xmm1)
			a2(pxor xmm1, xmm2)
			a2(pand xmm1, xmm5)
			a2(pxor xmm1, xmm2)
			a2(pxor xmm2, xmm3)
			a2(pand xmm2, xmm5)
			a2(pxor xmm2, xmm3)
			a2(pxor xmm3, xmm4)
			a2(pand xmm3, xmm5)
			a2(pxor xmm3, xmm4)
			a2(movdqa xmm4, xmm0)
			a2(movdqa xmm5, xmm3)
			a3(pshufd xmm2, xmm2, 0x4e)
			a3(pshufd xmm1, xmm1, 0x4e)
			a2(punpcklqdq xmm0, xmm2)
			a2(punpcklqdq xmm3, xmm1)
			a2(punpckhqdq xmm2, xmm4)
			a2(punpckhqdq xmm1, xmm5)
			a2(movdqa [%0+0], xmm0)
			a2(movdqa [%0+16], xmm3)
			a2(movdqa [%0+32], xmm2)
			a2(movdqa [%0+48], xmm1)
			asm_gcc_parms() :: "r"(blocks)
		asm_gcc_end()

		blocks += 16;
	}
}

#endif


/* msvc + x64 gcc get intrinsics */
#if defined(X86_INTRINSIC_SSE2)

#define SCRYPT_SALSA_SSE2

/*
	Default layout:
	 0  1  2  3
	 4  5  6  7
	 8  9 10 11
	12 13 14 15

	SSE2 layout:
	 0  5 10 15
	12  1  6 11
	 8 13  2  7
	 4  9 14  3
*/

static void
salsa_core_tangle_sse2(uint32_t *blocks, size_t count) {
	xmmi *st = (xmmi *)blocks;
	xmmi x0,x1,x2,x3;
	xmmi t0,t1;

	while (count--) {
		x0 = st[0];
		x3 = st[1];
		x2 = st[2];
		x1 = st[3];

		t0 = x0;
		t1 = _mm_srli_epi64(_mm_cmpeq_epi32(t0, t0), 32);

		x0 = _mm_xor_si128(x0, x3);
		x0 = _mm_and_si128(x0, t1);
		x0 = _mm_xor_si128(x0, x3);
		x3 = _mm_xor_si128(x3, x2);
		x3 = _mm_and_si128(x3, t1);
		x3 = _mm_xor_si128(x3, x2);
		x2 = _mm_xor_si128(x2, x1);
		x2 = _mm_and_si128(x2, t1);
		x2 = _mm_xor_si128(x2, x1);
		x1 = _mm_xor_si128(x1, t0);
		x1 = _mm_and_si128(x1, t1);
		x1 = _mm_xor_si128(x1, t0);

		t0 = x0;
		t1 = x3;
		x2 = _mm_shuffle_epi32(x2, 0x4e);
		x1 = _mm_shuffle_epi32(x1, 0x4e);
		x0 = _mm_unpacklo_epi64(x0, x2);
		x3 = _mm_unpacklo_epi64(x3, x1);
		x2 = _mm_unpackhi_epi64(x2, t0);
		x1 = _mm_unpackhi_epi64(x1, t1);

		st[0] = x0;
		st[1] = x1;
		st[2] = x2;
		st[3] = x3;

		st += 4;
	}
}

static void
salsa_core_untangle_sse2(uint32_t *blocks, size_t count) {
	xmmi *st = (xmmi *)blocks;
	xmmi x0,x1,x2,x3;
	xmmi t0,t1;

	while (count--) {
		x0 = st[0];
		x1 = st[1];
		x2 = st[2];
		x3 = st[3];

		t0 = x0;
		t1 = _mm_srli_epi64(_mm_cmpeq_epi32(t0, t0), 32);

		x0 = _mm_xor_si128(x0, x1);
		x0 = _mm_and_si128(x0, t1);
		x0 = _mm_xor_si128(x0, x1);
		x1 = _mm_xor_si128(x1, x2);
		x1 = _mm_and_si128(x1, t1);
		x1 = _mm_xor_si128(x1, x2);
		x2 = _mm_xor_si128(x2, x3);
		x2 = _mm_and_si128(x2, t1);
		x2 = _mm_xor_si128(x2, x3);
		x3 = _mm_xor_si128(x3, t0);
		x3 = _mm_and_si128(x3, t1);
		x3 = _mm_xor_si128(x3, t0);

		t0 = x0;
		t1 = x3;
		x2 = _mm_shuffle_epi32(x2, 0x4e);
		x1 = _mm_shuffle_epi32(x1, 0x4e);
		x0 = _mm_unpacklo_epi64(x0, x2);
		x3 = _mm_unpacklo_epi64(x3, x1);
		x2 = _mm_unpackhi_epi64(x2, t0);
		x1 = _mm_unpackhi_epi64(x1, t1);

		st[0] = x0;
		st[1] = x3;
		st[2] = x2;
		st[3] = x1;
		st += 4;
	}
}


static void INLINE
salsa_core_sse2(uint32_t state[16]) {
	size_t rounds = 8;
	xmmi *st = (xmmi *)state;
	xmmi x0 = st[0];
	xmmi x1 = st[1];
	xmmi x2 = st[2];
	xmmi x3 = st[3];
	xmmi x4;
	xmmi x5;

	for (; rounds; rounds -= 2) {
		x4 = x1;
		x4 = _mm_add_epi32(x4, x0);
		x5 = x4;
		x4 = _mm_slli_epi32(x4, 7);
		x5 = _mm_srli_epi32(x5, 25);
		x3 = _mm_xor_si128(x3, x4);
		x4 = x0;
		x3 = _mm_xor_si128(x3, x5);
		x4 = _mm_add_epi32(x4, x3);
		x5 = x4;
		x4 = _mm_slli_epi32(x4, 9);
		x5 = _mm_srli_epi32(x5, 23);
		x2 = _mm_xor_si128(x2, x4);
		x4 = x3;
		x2 = _mm_xor_si128(x2, x5);
		x3 = _mm_shuffle_epi32(x3, 0x93);
		x4 = _mm_add_epi32(x4, x2);
		x5 = x4;
		x4 = _mm_slli_epi32(x4, 13);
		x5 = _mm_srli_epi32(x5, 19);
		x1 = _mm_xor_si128(x1, x4);
		x4 = x2;
		x1 = _mm_xor_si128(x1, x5);
		x2 = _mm_shuffle_epi32(x2, 0x4e);
		x4 = _mm_add_epi32(x4, x1);
		x5 = x4;
		x4 = _mm_slli_epi32(x4, 18);
		x5 = _mm_srli_epi32(x5, 14);
		x0 = _mm_xor_si128(x0, x4);
		x4 = x3;
		x0 = _mm_xor_si128(x0, x5);
		x1 = _mm_shuffle_epi32(x1, 0x39);
		x4 = _mm_add_epi32(x4, x0);
		x5 = x4;
		x4 = _mm_slli_epi32(x4, 7);
		x5 = _mm_srli_epi32(x5, 25);
		x1 = _mm_xor_si128(x1, x4);
		x4 = x0;
		x1 = _mm_xor_si128(x1, x5);
		x4 = _mm_add_epi32(x4, x1);
		x5 = x4;
		x4 = _mm_slli_epi32(x4, 9);
		x5 = _mm_srli_epi32(x5, 23);
		x2 = _mm_xor_si128(x2, x4);
		x4 = x1;
		x2 = _mm_xor_si128(x2, x5);
		x1 = _mm_shuffle_epi32(x1, 0x93);
		x4 = _mm_add_epi32(x4, x2);
		x5 = x4;
		x4 = _mm_slli_epi32(x4, 13);
		x5 = _mm_srli_epi32(x5, 19);
		x3 = _mm_xor_si128(x3, x4);
		x4 = x2;
		x3 = _mm_xor_si128(x3, x5);
		x2 = _mm_shuffle_epi32(x2, 0x4e);
		x4 = _mm_add_epi32(x4, x3);
		x5 = x4;
		x4 = _mm_slli_epi32(x4, 18);
		x5 = _mm_srli_epi32(x5, 14);
		x0 = _mm_xor_si128(x0, x4);
		x3 = _mm_shuffle_epi32(x3, 0x39);
		x0 = _mm_xor_si128(x0, x5);
	}

	x0 = _mm_add_epi32(x0, st[0]);
	x1 = _mm_add_epi32(x1, st[1]);
	x2 = _mm_add_epi32(x2, st[2]);
	x3 = _mm_add_epi32(x3, st[3]);

	st[0] = x0;
	st[1] = x1;
	st[2] = x2;
	st[3] = x3;
}

#endif

