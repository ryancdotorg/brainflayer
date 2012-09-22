#define SCRYPT_MIX_BASE "Salsa20/8"

#define SCRYPT_BLOCK_BYTES 64
#define SCRYPT_BLOCK_DWORDS (SCRYPT_BLOCK_BYTES / sizeof(uint32_t))

/* must have these here in case block bytes is ever != 64 */
#include "scrypt-jane-romix-sse.h"
#include "scrypt-jane-romix-basic.h"

#include "scrypt-jane-mix_salsa-sse2.h"
#include "scrypt-jane-mix_salsa.h"

#if defined(SCRYPT_SALSA_SSE2)
	#define SCRYPT_CHUNKMIX_FN scrypt_ChunkMix_sse2
	#define SCRYPT_ROMIX_FN scrypt_ROMix_sse2
	#define SCRYPT_BLOCK_COPY_FN scrypt_block_copy_sse
	#define SCRYPT_BLOCK_XOR_FN scrypt_block_xor_sse
	#define SCRYPT_COPY_FN scrypt_copy_sse
	#define SCRYPT_XOR_FN scrypt_xor_sse
	#define SCRYPT_MIX_FN salsa_core_sse2
	#define SCRYPT_ROMIX_TANGLE_FN salsa_core_tangle_sse2
	#define SCRYPT_ROMIX_UNTANGLE_FN salsa_core_untangle_sse2
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
#define SCRYPT_MIX_FN salsa_core_basic
#define SCRYPT_ROMIX_TANGLE_FN scrypt_romix_convert_endian
#define SCRYPT_ROMIX_UNTANGLE_FN scrypt_romix_convert_endian
#include "scrypt-jane-romix-template.h"

#if !defined(SCRYPT_CHOOSE_COMPILETIME)
static scrypt_ROMixfn
scrypt_getROMix() {
	size_t cpuflags = detect_cpu();

#if defined(SCRYPT_SALSA_SSE2)
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

#if defined(SCRYPT_SALSA_SSE2)
		flags |= cpu_sse2;
#endif

	return flags;
}
#endif


static int
scrypt_test_mix() {
	static const uint8_t expected[16] = {
		0x27,0x30,0x24,0x5f,0x07,0xa4,0x85,0x47,0xe4,0xef,0x13,0x81,0x3a,0x62,0x4f,0x8c,
	};

	int ret = 1;
	size_t cpuflags = detect_cpu();

#if defined(SCRYPT_SALSA_SSE2)
	if (cpuflags & cpu_sse2)
		ret &= scrypt_test_mix_instance(scrypt_ChunkMix_sse2, salsa_core_tangle_sse2, salsa_core_untangle_sse2, expected);
#endif

#if defined(SCRYPT_SALSA_BASIC)
	ret &= scrypt_test_mix_instance(scrypt_ChunkMix_basic, scrypt_romix_convert_endian, scrypt_romix_convert_endian, expected);
#endif

	return ret;
}
