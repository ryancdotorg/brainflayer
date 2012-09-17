#if !defined(SCRYPT_CHOOSE_COMPILETIME)
typedef void (FASTCALL *scrypt_ROMixfn)(uint8_t *X/*[chunkBytes]*/, uint8_t *Y/*[chunkBytes]*/, uint8_t *V/*[chunkBytes * N]*/, uint32_t N, uint32_t r);
#endif

static void
scrypt_romix_nop(uint32_t *blocks, size_t count) {
}

static void
scrypt_romix_convert_endian(uint32_t *blocks, size_t count) {
#if !defined(CPU_LE)
	static const union { uint8_t b[2]; uint16_t w; } endian_test = {{1,0}};
	size_t i;
	if (endian_test.w == 0x100) {
		count *= (SCRYPT_BLOCK_BYTES / 4);
		while (count--)
			U32_SWAP(blocks[0]);
	}
#endif
}

typedef void (*mixfn)(uint32_t *block);
typedef void (*blockfixfn)(uint32_t *blocks, size_t count);

static int
scrypt_test_mix_instance(mixfn mixfn, blockfixfn prefn, blockfixfn postfn, const uint8_t expected[16]) {
	uint32_t MM16 block[16], v;
	uint8_t final[16];
	size_t i;

	for (i = 0; i < 16; i++) {
		v = (uint32_t)i;
		v = (v << 8) | v;
		v = (v << 16) | v;
		block[i] = v;
	}

	prefn(block, 1);
	for (i = 0; i < 257; i++)
		mixfn(block);
	postfn(block, 1);

	U32TO8_LE(final + 0, block[0]);
	U32TO8_LE(final + 4, block[1]);
	U32TO8_LE(final + 8, block[2]);
	U32TO8_LE(final + 12, block[3]);

	return scrypt_verify(expected, final, 16);
}

#if defined(SCRYPT_CHACHA)
#include "scrypt-jane-chacha.h"
#elif defined(SCRYPT_SALSA)
#include "scrypt-jane-salsa.h"
#else
	#define SCRYPT_MIX_BASE "ERROR"
	#define SCRYPT_BLOCK_BYTES 64
	#if !defined(SCRYPT_CHOOSE_COMPILETIME)
		static void FASTCALL scrypt_ROMix_error(uint8_t *X/*[chunkBytes]*/, uint8_t *Y/*[chunkBytes]*/, uint8_t *V/*[chunkBytes * N]*/, uint32_t N, uint32_t r) {}
		static scrypt_ROMixfn scrypt_getROMix() { return scrypt_ROMix_error; }
	#else
		static void FASTCALL scrypt_ROMix(uint8_t *X, uint8_t *Y, uint8_t *V, uint32_t N, uint32_t r) {}
	#endif
	static int scrypt_test_mix() { return 0; }
	#error must define a mix function!
#endif

#if !defined(SCRYPT_CHOOSE_COMPILETIME)
#undef SCRYPT_MIX
#define SCRYPT_MIX SCRYPT_MIX_BASE
#endif
