/* x86 */
#if defined(X86ASM_SSE2) && (!defined(SCRYPT_CHOOSE_COMPILETIME) || (!defined(SCRYPT_SALSA_INCLUDED) && defined(SYSTEM_SSE2)))

#define SCRYPT_SALSA_SSE2

asm_naked_fn_proto(void, salsa_core_tangle_sse2)(uint32_t *blocks, size_t count)
asm_naked_fn(salsa_core_tangle_sse2)
	a2(mov eax, [esp+4])
	a2(mov edx, [esp+8])
	a1(salsa_core_tangle_sse2_loop:)
		a2(movdqa xmm0, [eax+0])
		a2(movdqa xmm3, [eax+16])
		a2(movdqa xmm2, [eax+32])
		a2(movdqa xmm1, [eax+48])
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
		a2(movdqa [eax+0], xmm0)
		a2(movdqa [eax+16], xmm1)
		a2(movdqa [eax+32], xmm2)
		a2(movdqa [eax+48], xmm3)
		a2(add eax, 64)
		a2(sub edx, 1)
		a1(jnz salsa_core_tangle_sse2_loop)
	a1(ret 8)
asm_naked_fn_end(salsa_core_tangle_sse2)

asm_naked_fn_proto(void, salsa_core_untangle_sse2)(uint32_t *blocks, size_t count)
asm_naked_fn(salsa_core_untangle_sse2)
	a2(mov eax, [esp+4])
	a2(mov edx, [esp+8])
	a1(salsa_core_untangle_sse2_loop:)
		a2(movdqa xmm0, [eax+0])
		a2(movdqa xmm1, [eax+16])
		a2(movdqa xmm2, [eax+32])
		a2(movdqa xmm3, [eax+48])
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
		a2(movdqa [eax+0], xmm0)
		a2(movdqa [eax+16], xmm3)
		a2(movdqa [eax+32], xmm2)
		a2(movdqa [eax+48], xmm1)
		a2(add eax, 64)
		a2(sub edx, 1)
		a1(jnz salsa_core_untangle_sse2_loop)
	a1(ret 8)
asm_naked_fn_end(salsa_core_tangle_sse2)

asm_naked_fn_proto(void, scrypt_ChunkMix_sse2)(uint8_t *Bout/*[chunkBytes]*/, uint8_t *Bin/*[chunkBytes]*/, uint32_t r)
asm_naked_fn(scrypt_ChunkMix_sse2)
	a1(push ebx)
	a1(push edi)
	a1(push esi)
	a1(push ebp)
	a2(mov ebp,esp)
	a2(mov edi,[ebp+20])
	a2(mov esi,[ebp+24])
	a2(mov ebx,[ebp+28])
	a2(sub esp,64)
	a2(and esp,~63)
	a2(lea edx,[ebx*2])
	a2(shl edx,6)
	a2(lea eax,[edx-64])
	a2(add eax,esi)
	a2(xor ecx,ecx)
	a2(xor ebx,ebx)
	a2(movdqa xmm0,[eax+0])
	a2(movdqa xmm1,[eax+16])
	a2(movdqa xmm2,[eax+32])
	a2(movdqa xmm3,[eax+48])
	a1(scrypt_ChunkMix_sse2_loop:)
		a2(pxor xmm0,[esi+ecx+0])
		a2(pxor xmm1,[esi+ecx+16])
		a2(pxor xmm2,[esi+ecx+32])
		a2(pxor xmm3,[esi+ecx+48])
		a2(movdqa [esp+0],xmm0)
		a2(movdqa [esp+16],xmm1)
		a2(movdqa xmm6,xmm2)
		a2(movdqa xmm7,xmm3)
		a2(mov eax,8)
		a1(scrypt_salsa_sse2_loop: )
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
			a2(sub eax, 2)
			a2(movdqa xmm5, xmm4)
			a2(pslld xmm4, 18)
			a2(psrld xmm5, 14)
			a2(pxor xmm0, xmm4)
			a3(pshufd xmm3, xmm3, 0x39)
			a2(pxor xmm0, xmm5)
			a1(ja scrypt_salsa_sse2_loop)
		a2(paddd xmm0,[esp+0])
		a2(paddd xmm1,[esp+16])
		a2(paddd xmm2,xmm6)
		a2(paddd xmm3,xmm7)
		a2(lea eax,[ebx+ecx])
		a2(xor ebx,edx)
		a2(and eax,~0x7f)
		a2(add ecx,64)
		a2(shr eax,1)
		a2(add eax, edi)
		a2(cmp ecx,edx)
		a2(movdqa [eax+0],xmm0)
		a2(movdqa [eax+16],xmm1)
		a2(movdqa [eax+32],xmm2)
		a2(movdqa [eax+48],xmm3)		
		a1(jne scrypt_ChunkMix_sse2_loop)
	a2(mov esp,ebp)
	a1(pop ebp)
	a1(pop esi)
	a1(pop edi)
	a1(pop ebx)
	a1(ret 12)
asm_naked_fn_end(scrypt_ChunkMix_sse2)

#endif



/* x64 */
#if defined(X86_64ASM_SSE2) && (!defined(SCRYPT_CHOOSE_COMPILETIME) || (!defined(SCRYPT_SALSA_INCLUDED) && defined(SYSTEM_SSE2)))

#define SCRYPT_SALSA_SSE2

asm_naked_fn_proto(void, salsa_core_tangle_sse2)(uint32_t *blocks, size_t count)
asm_naked_fn(salsa_core_tangle_sse2)
	a1(salsa_core_tangle_sse2_loop:)
		a2(movdqa xmm0, [rdi+0])
		a2(movdqa xmm3, [rdi+16])
		a2(movdqa xmm2, [rdi+32])
		a2(movdqa xmm1, [rdi+48])
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
		a2(movdqa [rdi+0], xmm0)
		a2(movdqa [rdi+16], xmm1)
		a2(movdqa [rdi+32], xmm2)
		a2(movdqa [rdi+48], xmm3)
		a2(add rdi, 64)
		a2(sub rsi, 1)
		a1(jnz salsa_core_tangle_sse2_loop)
	a1(ret)
asm_naked_fn_end(salsa_core_tangle_sse2)

asm_naked_fn_proto(void, salsa_core_untangle_sse2)(uint32_t *blocks, size_t count)
asm_naked_fn(salsa_core_untangle_sse2)
	a1(salsa_core_untangle_sse2_loop:)
		a2(movdqa xmm0, [rdi+0])
		a2(movdqa xmm1, [rdi+16])
		a2(movdqa xmm2, [rdi+32])
		a2(movdqa xmm3, [rdi+48])
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
		a2(movdqa [rdi+0], xmm0)
		a2(movdqa [rdi+16], xmm3)
		a2(movdqa [rdi+32], xmm2)
		a2(movdqa [rdi+48], xmm1)
		a2(add rdi, 64)
		a2(sub rsi, 1)
		a1(jnz salsa_core_untangle_sse2_loop)
	a1(ret)
asm_naked_fn_end(salsa_core_tangle_sse2)

asm_naked_fn_proto(void, scrypt_ChunkMix_sse2)(uint8_t *Bout/*[chunkBytes]*/, uint8_t *Bin/*[chunkBytes]*/, uint32_t r)
asm_naked_fn(scrypt_ChunkMix_sse2)
	a2(lea rdx,[rdx*2])
	a2(shl rdx,6)
	a2(lea rax,[rdx-64])
	a2(add rax,rsi)
	a2(xor rcx,rcx)
	a2(xor r8,r8)
	a2(movdqa xmm0,[rax+0])
	a2(movdqa xmm1,[rax+16])
	a2(movdqa xmm2,[rax+32])
	a2(movdqa xmm3,[rax+48])
	a1(scrypt_ChunkMix_sse2_loop:)
		a2(pxor xmm0,[rsi+rcx+0])
		a2(pxor xmm1,[rsi+rcx+16])
		a2(pxor xmm2,[rsi+rcx+32])
		a2(pxor xmm3,[rsi+rcx+48])
		a2(movdqa xmm8,xmm0)
		a2(movdqa xmm9,xmm1)
		a2(movdqa xmm10,xmm2)
		a2(movdqa xmm11,xmm3)
		a2(mov rax,8)
		a1(scrypt_salsa_sse2_loop: )
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
			a2(sub rax, 2)
			a2(movdqa xmm5, xmm4)
			a2(pslld xmm4, 18)
			a2(psrld xmm5, 14)
			a2(pxor xmm0, xmm4)
			a3(pshufd xmm3, xmm3, 0x39)
			a2(pxor xmm0, xmm5)
			a1(ja scrypt_salsa_sse2_loop)
		a2(paddd xmm0,xmm8)
		a2(paddd xmm1,xmm9)
		a2(paddd xmm2,xmm10)
		a2(paddd xmm3,xmm11)
		a2(lea rax,[r8+rcx])
		a2(xor r8,rdx)
		a2(and rax,~0x7f)
		a2(add rcx,64)
		a2(shr rax,1)
		a2(add rax, rdi)
		a2(cmp rcx,rdx)
		a2(movdqa [rax+0],xmm0)
		a2(movdqa [rax+16],xmm1)
		a2(movdqa [rax+32],xmm2)
		a2(movdqa [rax+48],xmm3)		
		a1(jne scrypt_ChunkMix_sse2_loop)
	a1(ret)
asm_naked_fn_end(scrypt_ChunkMix_sse2)

#endif


/* intrinsic */
#if defined(X86_INTRINSIC_SSE2) && (!defined(SCRYPT_CHOOSE_COMPILETIME) || !defined(SCRYPT_SALSA_INCLUDED)) && !defined(SCRYPT_SALSA_SSE2)

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

static void
scrypt_ChunkMix_sse2(uint8_t *Bout/*[chunkBytes]*/, uint8_t *Bin/*[chunkBytes]*/, uint32_t r) {
	uint32_t i, blocksPerChunk = r * 2, half = 0;
	xmmi *xmmp,x0,x1,x2,x3,x4,x5,t0,t1,t2,t3;
	size_t rounds;

	/* 1: X = B_{2r - 1} */
	xmmp = (xmmi *)scrypt_block(Bin, blocksPerChunk - 1);
	x0 = xmmp[0];
	x1 = xmmp[1];
	x2 = xmmp[2];
	x3 = xmmp[3];

	/* 2: for i = 0 to 2r - 1 do */
	for (i = 0; i < blocksPerChunk; i++, half ^= r) {
		/* 3: X = H(X ^ B_i) */
		xmmp = (xmmi *)scrypt_block(Bin, i);
		x0 = _mm_xor_si128(x0, xmmp[0]);
		x1 = _mm_xor_si128(x1, xmmp[1]);
		x2 = _mm_xor_si128(x2, xmmp[2]);
		x3 = _mm_xor_si128(x3, xmmp[3]);

		t0 = x0;
		t1 = x1;
		t2 = x2;
		t3 = x3;

		for (rounds = 8; rounds; rounds -= 2) {
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

		x0 = _mm_add_epi32(x0, t0);
		x1 = _mm_add_epi32(x1, t1);
		x2 = _mm_add_epi32(x2, t2);
		x3 = _mm_add_epi32(x3, t3);

		/* 4: Y_i = X */
		/* 6: B'[0..r-1] = Y_even */
		/* 6: B'[r..2r-1] = Y_odd */
		xmmp = (xmmi *)scrypt_block(Bout, (i / 2) + half);
		xmmp[0] = x0;
		xmmp[1] = x1;
		xmmp[2] = x2;
		xmmp[3] = x3;
	}
}

#endif

#if defined(SCRYPT_SALSA_SSE2)
	#undef SCRYPT_MIX
	#define SCRYPT_MIX "Salsa/8-SSE2"
	#undef SCRYPT_SALSA_INCLUDED
	#define SCRYPT_SALSA_INCLUDED
#endif
