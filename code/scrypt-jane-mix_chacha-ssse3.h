/* x86/64 gcc gets inline asm */
#if (!defined(SCRYPT_CHOOSE_COMPILETIME) && defined(COMPILER_GCC) && (defined(X86ASM_SSSE3) || defined(X86_64ASM_SSSE3)))

#undef SCRYPT_MIX
#define SCRYPT_MIX "ChaCha20/8 SSSE3"

#undef SCRYPT_CHACHA_INCLUDED
#define SCRYPT_CHACHA_INCLUDED
#define SCRYPT_CHACHA_SSSE3

static void INLINE
chacha_core_ssse3(uint32_t state[16]) {
	size_t rounds = 8;
	asm_gcc()
		a2(movdqa xmm4,[ssse3_rotl16_32bit])
		a2(movdqa xmm5,[ssse3_rotl8_32bit])
		a2(movdqa xmm0,[%1+0])
		a2(movdqa xmm1,[%1+16])
		a2(movdqa xmm2,[%1+32])
		a2(movdqa xmm3,[%1+48])
		a1(1: )
		a2(paddd xmm0,xmm1)
		a2(pxor  xmm3,xmm0)
		a2(pshufb xmm3,xmm4)
		a2(paddd xmm2,xmm3)
		a2(pxor  xmm1,xmm2)
		a2(movdqa xmm6,xmm1)
		a2(pslld xmm1,12)
		a2(psrld xmm6,20)
		a2(pxor  xmm1,xmm6)
		a2(paddd xmm0,xmm1)
		a2(pxor  xmm3,xmm0)
		a2(pshufb xmm3,xmm5)
		a3(pshufd xmm0,xmm0,0x93)
		a2(paddd xmm2,xmm3)
		a3(pshufd xmm3,xmm3,0x4e)
		a2(pxor  xmm1,xmm2)
		a3(pshufd xmm2,xmm2,0x39)
		a2(movdqa xmm6,xmm1)
		a2(pslld xmm1,7)
		a2(psrld xmm6,25)
		a2(pxor  xmm1,xmm6)
		a2(sub   %0,2)
		a2(paddd xmm0,xmm1)
		a2(pxor  xmm3,xmm0)
		a2(pshufb xmm3,xmm4)
		a2(paddd xmm2,xmm3)
		a2(pxor  xmm1,xmm2)
		a2(movdqa xmm6,xmm1)
		a2(pslld xmm1,12)
		a2(psrld xmm6,20)
		a2(pxor  xmm1,xmm6)
		a2(paddd xmm0,xmm1)
		a2(pxor  xmm3,xmm0)
		a2(pshufb xmm3,xmm5)
		a3(pshufd xmm0,xmm0,0x39)
		a2(paddd xmm2,xmm3)
		a3(pshufd xmm3,xmm3,0x4e)
		a2(pxor  xmm1,xmm2)
		a3(pshufd xmm2,xmm2,0x93)
		a2(movdqa xmm6,xmm1)
		a2(pslld xmm1,7)
		a2(psrld xmm6,25)
		a2(pxor  xmm1,xmm6)
		a1(ja 1b)
		a2(paddd xmm0,[%1+0])
		a2(paddd xmm1,[%1+16])
		a2(paddd xmm2,[%1+32])
		a2(paddd xmm3,[%1+48])
		a2(movdqa [%1+0],xmm0)
		a2(movdqa [%1+16],xmm1)
		a2(movdqa [%1+32],xmm2)
		a2(movdqa [%1+48],xmm3)
		asm_gcc_parms() : "+r"(rounds) : "r"(state) : "cc", "memory"
#if defined(SYSTEM_SSE)
		, "%xmm0", "%xmm1", "%xmm2", "%xmm3", "%xmm4", "%xmm5", "%xmm6"
#endif
	asm_gcc_end()
}

#endif


/* msvc gets intrinsics */
#if defined(X86_INTRINSIC_SSSE3) && (!defined(SCRYPT_CHOOSE_COMPILETIME) || !defined(SCRYPT_CHACHA_INCLUDED))

#undef SCRYPT_MIX
#define SCRYPT_MIX "ChaCha20/8 SSSE3i"

#undef SCRYPT_CHACHA_INCLUDED
#define SCRYPT_CHACHA_INCLUDED
#define SCRYPT_CHACHA_SSSE3

static void INLINE
chacha_core_ssse3(uint32_t state[16]) {
	size_t rounds = 8;
	xmmi *st = (xmmi *)state;
	xmmi x0 = st[0];
	xmmi x1 = st[1];
	xmmi x2 = st[2];
	xmmi x3 = st[3];
	xmmi x4 = *(xmmi *)&ssse3_rotl16_32bit;
	xmmi x5 = *(xmmi *)&ssse3_rotl8_32bit;
	xmmi x6;

	for (; rounds; rounds -= 2) {
		x0 = _mm_add_epi32(x0, x1);
		x3 = _mm_xor_si128(x3, x0);
		x3 = _mm_shuffle_epi8(x3, x4);
		x2 = _mm_add_epi32(x2, x3);
		x1 = _mm_xor_si128(x1, x2);
		x6 = x1;
		x1 = _mm_or_si128(_mm_slli_epi32(x1, 12), _mm_srli_epi32(x6, 20));
		x0 = _mm_add_epi32(x0, x1);
		x3 = _mm_xor_si128(x3, x0);
		x3 = _mm_shuffle_epi8(x3, x5);
		x0 = _mm_shuffle_epi32(x0, 0x93);
		x2 = _mm_add_epi32(x2, x3);
		x3 = _mm_shuffle_epi32(x3, 0x4e);
		x1 = _mm_xor_si128(x1, x2);
		x2 = _mm_shuffle_epi32(x2, 0x39);
		x6 = x1;
		x1 = _mm_or_si128(_mm_slli_epi32(x1, 7), _mm_srli_epi32(x6, 25));
		x0 = _mm_add_epi32(x0, x1);
		x3 = _mm_xor_si128(x3, x0);
		x3 = _mm_shuffle_epi8(x3, x4);
		x2 = _mm_add_epi32(x2, x3);
		x1 = _mm_xor_si128(x1, x2);
		x6 = x1;
		x1 = _mm_or_si128(_mm_slli_epi32(x1, 12), _mm_srli_epi32(x6, 20));
		x0 = _mm_add_epi32(x0, x1);
		x3 = _mm_xor_si128(x3, x0);
		x3 = _mm_shuffle_epi8(x3, x5);
		x0 = _mm_shuffle_epi32(x0, 0x39);
		x2 = _mm_add_epi32(x2, x3);
		x3 = _mm_shuffle_epi32(x3, 0x4e);
		x1 = _mm_xor_si128(x1, x2);
		x2 = _mm_shuffle_epi32(x2, 0x93);
		x6 = x1;
		x1 = _mm_or_si128(_mm_slli_epi32(x1, 7), _mm_srli_epi32(x6, 25));
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
