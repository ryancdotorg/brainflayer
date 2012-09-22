/* sse block operations */

/* x86/64 gcc gets inline asm */
#if defined(COMPILER_GCC) && (defined(X86ASM_SSE) || defined(X86_64ASM))

#define SCRYPT_BLOCKOP_SSE

static void INLINE
scrypt_copy_sse(uint32_t *dst, const uint32_t *src, uint32_t len) {
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
		a2(sub %0, 16)
		a1(jnz 1b)
		asm_gcc_parms() : "+r"(len), "+r"(dst), "+r"(src) :: "cc", "memory"
#if defined(SYSTEM_SSE)
		, "%xmm0", "%xmm1", "%xmm2", "%xmm3"
#endif
	asm_gcc_end()
}

static void INLINE
scrypt_xor_sse(uint32_t *dst, const uint32_t *src, uint32_t len) {
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
		a2(sub %0, 16)
		a1(jnz 1b)
		asm_gcc_parms() : "+r"(len), "+r"(dst), "+r"(src) :: "cc", "memory"
#if defined(SYSTEM_SSE)
		, "%xmm0", "%xmm1", "%xmm2", "%xmm3", "%xmm4", "%xmm5", "%xmm6", "%xmm7"
#endif
	asm_gcc_end()
}

#endif


/* intrinsics */
#if defined(X86_INTRINSIC_SSE)
static void INLINE
scrypt_copy_sse(uint32_t *dst, const uint32_t *src, uint32_t len) {
	xmm x0,x1,x2,x3;
	for (len /= 16; len; len--, dst += 16, src += 16) {
		x0 = _mm_load_ps((float *)src + 0);
		x1 = _mm_load_ps((float *)src + 4);
		x2 = _mm_load_ps((float *)src + 8);
		x3 = _mm_load_ps((float *)src + 12);
		_mm_store_ps((float *)dst + 0, x0);
		_mm_store_ps((float *)dst + 4, x1);
		_mm_store_ps((float *)dst + 8, x2);
		_mm_store_ps((float *)dst + 12, x3);
	}
}

static void INLINE
scrypt_xor_sse(uint32_t *dst, const uint32_t *src, uint32_t len) {
	xmm x0,x1,x2,x3,x4,x5,x6,x7;
	for (len /= 16; len; len--, dst += 16, src += 16) {
		x0 = _mm_load_ps((float *)src + 0);
		x1 = _mm_load_ps((float *)src + 4);
		x2 = _mm_load_ps((float *)src + 8);
		x3 = _mm_load_ps((float *)src + 12);
		x4 = _mm_load_ps((float *)dst + 0);
		x5 = _mm_load_ps((float *)dst + 4);
		x6 = _mm_load_ps((float *)dst + 8);
		x7 = _mm_load_ps((float *)dst + 12);
		x0 = _mm_xor_ps(x0, x4);
		x1 = _mm_xor_ps(x1, x5);
		x2 = _mm_xor_ps(x2, x6);
		x3 = _mm_xor_ps(x3, x7);
		_mm_store_ps((float *)dst + 0, x0);
		_mm_store_ps((float *)dst + 4, x1);
		_mm_store_ps((float *)dst + 8, x2);
		_mm_store_ps((float *)dst + 12, x3);
	}
}
#endif
