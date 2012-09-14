/* sse block operations */

/* x86/64 gcc gets inline asm */
#if (defined(COMPILER_GCC) && (defined(X86ASM_SSE) || defined(X86_64ASM))) || (defined(SYSTEM_SSE) && !defined(SCRYPT_BLOCKOP_INCLUDED))

#define SCRYPT_BLOCKOP_INCLUDED
#define SCRYPT_BLOCKOP_SSE

static void INLINE
scrypt_copy_sse(uint8_t *dst, const uint8_t *src, uint32_t len) {
	asm_gcc()
		a2(sub %2, %1)
		a1(1:)
		a2(movaps xmm0, [%1+%2+0])
		a2(movaps xmm1, [%1+%2+16])
		a2(movaps xmm2, [%1+%2+32])
		a2(movaps xmm3, [%1+%2+48])
		a2(movaps [%1+0], xmm0)
		a2(movaps [%1+16], xmm1)
		a2(movaps [%1+32], xmm2)
		a2(movaps [%1+48], xmm3)
		a2(add %1, 64)
		a2(sub %0, 64)
		a1(jnz 1b)
		asm_gcc_parms() : "+r"(len), "+r"(dst), "+r"(src) :: "cc", "memory"
	asm_gcc_end()
}

static void INLINE
scrypt_xor_sse(uint8_t *dst, const uint8_t *src, uint32_t len) {
	asm_gcc()
		a2(sub %2, %1)
		a1(1:)
		a2(movaps xmm0, [%1+%2+0])
		a2(movaps xmm1, [%1+%2+16])
		a2(movaps xmm2, [%1+%2+32])
		a2(movaps xmm3, [%1+%2+48])
		a2(movaps xmm4, [%1+0])
		a2(movaps xmm5, [%1+16])
		a2(movaps xmm6, [%1+32])
		a2(movaps xmm7, [%1+48])
		a2(xorps xmm0, xmm4)
		a2(xorps xmm1, xmm5)
		a2(xorps xmm2, xmm6)
		a2(xorps xmm3, xmm7)
		a2(movaps [%1+0], xmm0)
		a2(movaps [%1+16], xmm1)
		a2(movaps [%1+32], xmm2)
		a2(movaps [%1+48], xmm3)
		a2(add %1, 64)
		a2(sub %0, 64)
		a1(jnz 1b)
		asm_gcc_parms() : "+r"(len), "+r"(dst), "+r"(src) :: "cc", "memory"
	asm_gcc_end()
}

static void INLINE
scrypt_block_copy_sse(uint8_t *dst, const uint8_t *src) {
	asm_gcc()
		a2(movaps xmm0, [%1+0])
		a2(movaps xmm1, [%1+16])
		a2(movaps xmm2, [%1+32])
		a2(movaps xmm3, [%1+48])
		a2(movaps [%0+0], xmm0)
		a2(movaps [%0+16], xmm1)
		a2(movaps [%0+32], xmm2)
		a2(movaps [%0+48], xmm3)
		asm_gcc_parms() : : "r"(dst), "r"(src)
	asm_gcc_end()
}

static void INLINE
scrypt_block_xor_sse(uint8_t *dst, const uint8_t *src) {
	asm_gcc()
		a2(movaps xmm0, [%1+0])
		a2(movaps xmm1, [%1+16])
		a2(movaps xmm2, [%1+32])
		a2(movaps xmm3, [%1+48])
		a2(movaps xmm4, [%0+0])
		a2(movaps xmm5, [%0+16])
		a2(movaps xmm6, [%0+32])
		a2(movaps xmm7, [%0+48])
		a2(xorps xmm0, xmm4)
		a2(xorps xmm1, xmm5)
		a2(xorps xmm2, xmm6)
		a2(xorps xmm3, xmm7)
		a2(movaps [%0+0], xmm0)
		a2(movaps [%0+16], xmm1)
		a2(movaps [%0+32], xmm2)
		a2(movaps [%0+48], xmm3)
		asm_gcc_parms() : : "r"(dst), "r"(src)
	asm_gcc_end()
}
#endif


/* msvc + x64 gcc gets intrinsics */
#if defined(X86_INTRINSIC_SSE)

#define SCRYPT_SSE

static void INLINE
scrypt_copy_sse(uint8_t *dst, const uint8_t *src, uint32_t len) {
	xmm *d = (xmm *)dst, *s = (xmm *)src;
	for (len /= 64; len; len--, d += 4, s += 4) {
		d[0] = s[0];
		d[1] = s[1];
		d[2] = s[2];
		d[3] = s[3];
	}
}

static void INLINE
scrypt_xor_sse(uint8_t *dst, const uint8_t *src, uint32_t len) {
	xmm *d = (xmm *)dst;
	const xmm *s = (const xmm *)src;
	for (len /= 64; len; len--, d += 4, s += 4) {
		d[0] = _mm_xor_ps(d[0], s[0]);
		d[1] = _mm_xor_ps(d[1], s[1]);
		d[2] = _mm_xor_ps(d[2], s[2]);
		d[3] = _mm_xor_ps(d[3], s[3]);
	}
}

static void INLINE
scrypt_block_copy_sse(uint8_t *dst, const uint8_t *src) {
	xmm *d = (xmm *)dst, *s = (xmm *)src;
	d[0] = s[0];
	d[1] = s[1];
	d[2] = s[2];
	d[3] = s[3];
}

static void INLINE
scrypt_block_xor_sse(uint8_t *dst, const uint8_t *src) {
	xmm *d = (xmm *)dst;
	const xmm *s = (const xmm *)src;
	d[0] = _mm_xor_ps(d[0], s[0]);
	d[1] = _mm_xor_ps(d[1], s[1]);
	d[2] = _mm_xor_ps(d[2], s[2]);
	d[3] = _mm_xor_ps(d[3], s[3]);
}
#endif
