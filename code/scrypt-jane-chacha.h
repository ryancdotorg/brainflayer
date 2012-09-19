#define SCRYPT_MIX_BASE "ChaCha20/8"

#define SCRYPT_BLOCK_BYTES 64

/* must have these here in case block bytes is ever != 64 */
#include "scrypt-jane-romix-sse.h"
#include "scrypt-jane-romix-basic.h"

#include "scrypt-jane-mix_chacha-ssse3.h"
#include "scrypt-jane-mix_chacha-sse2.h"
#include "scrypt-jane-mix_chacha.h"

#if defined(SCRYPT_CHACHA_SSSE3)
	#define SCRYPT_CHUNKMIX_FN scrypt_ChunkMix_ssse3
	#define SCRYPT_ROMIX_FN scrypt_ROMix_ssse3
	#define SCRYPT_BLOCK_COPY_FN scrypt_block_copy_sse
	#define SCRYPT_BLOCK_XOR_FN scrypt_block_xor_sse
	#define SCRYPT_COPY_FN scrypt_copy_sse
	#define SCRYPT_XOR_FN scrypt_xor_sse
	#define SCRYPT_MIX_FN chacha_core_ssse3
	#define SCRYPT_ROMIX_TANGLE_FN scrypt_romix_nop
	#define SCRYPT_ROMIX_UNTANGLE_FN scrypt_romix_nop
	#define SCRYPT_ROMIX_OVERRIDE_CHUNKMIX
	#include "scrypt-jane-romix-template.h"
#endif

#if defined(SCRYPT_CHACHA_SSE2)
	#define SCRYPT_CHUNKMIX_FN scrypt_ChunkMix_sse2
	#define SCRYPT_ROMIX_FN scrypt_ROMix_sse2
	#define SCRYPT_BLOCK_COPY_FN scrypt_block_copy_sse
	#define SCRYPT_BLOCK_XOR_FN scrypt_block_xor_sse
	#define SCRYPT_COPY_FN scrypt_copy_sse
	#define SCRYPT_XOR_FN scrypt_xor_sse
	#define SCRYPT_MIX_FN chacha_core_sse2
	#define SCRYPT_ROMIX_TANGLE_FN scrypt_romix_nop
	#define SCRYPT_ROMIX_UNTANGLE_FN scrypt_romix_nop
	#define SCRYPT_ROMIX_OVERRIDE_CHUNKMIX
	#include "scrypt-jane-romix-template.h"
#endif

/* cpu agnostic */
#define SCRYPT_CHUNKMIX_FN scrypt_ChunkMix_basic
#define SCRYPT_ROMIX_FN scrypt_ROMix_basic
#define SCRYPT_BLOCK_COPY_FN scrypt_block_copy_basic
#define SCRYPT_BLOCK_XOR_FN scrypt_block_xor_basic
#define SCRYPT_COPY_FN scrypt_copy_basic
#define SCRYPT_XOR_FN scrypt_xor_basic
#define SCRYPT_MIX_FN chacha_core_basic
#define SCRYPT_ROMIX_TANGLE_FN scrypt_romix_convert_endian
#define SCRYPT_ROMIX_UNTANGLE_FN scrypt_romix_convert_endian
#include "scrypt-jane-romix-template.h"

#if !defined(SCRYPT_CHOOSE_COMPILETIME)
static scrypt_ROMixfn
scrypt_getROMix() {
	size_t cpuflags = detect_cpu();
#if defined(SCRYPT_CHACHA_SSSE3)
	if (cpuflags & cpu_ssse3)
		return scrypt_ROMix_ssse3;
	else
#endif

#if defined(SCRYPT_CHACHA_SSE2)
	if (cpuflags & cpu_sse2)
		return scrypt_ROMix_sse2;
	else
#endif

	return scrypt_ROMix_basic;
}
#endif


#if defined(SCRYPT_TEST_SPEED)
static size_t
available_implementations() {
	size_t flags = 0;

#if defined(SCRYPT_CHACHA_SSSE3)
	flags |= cpu_ssse3;
#endif

#if defined(SCRYPT_CHACHA_SSE2)
		flags |= cpu_sse2;
#endif

	return flags;
}
#endif

static int
scrypt_test_mix() {
	static const uint8_t expected[16] = {
		0x16,0x90,0xc1,0x49,0x8c,0xfb,0x17,0x89,0x81,0x17,0x83,0x96,0xc4,0x6c,0x75,0xcf,
	};

	int ret = 1;
	size_t cpuflags = detect_cpu();

#if defined(SCRYPT_CHACHA_SSSE3)
	if (cpuflags & cpu_ssse3)
		ret &= scrypt_test_mix_instance(scrypt_ChunkMix_ssse3, scrypt_romix_nop, scrypt_romix_nop, expected);
#endif

#if defined(SCRYPT_CHACHA_SSE2)
	if (cpuflags & cpu_sse2)
		ret &= scrypt_test_mix_instance(scrypt_ChunkMix_sse2, scrypt_romix_nop, scrypt_romix_nop, expected);
#endif

#if defined(SCRYPT_CHACHA_BASIC)
	ret &= scrypt_test_mix_instance(scrypt_ChunkMix_basic, scrypt_romix_convert_endian, scrypt_romix_convert_endian, expected);
#endif

	return ret;
}

