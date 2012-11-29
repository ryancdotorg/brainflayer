#if !defined(SCRYPT_CHOOSE_COMPILETIME)
typedef void (FASTCALL *scrypt_ROMixfn)(uint32_t *X/*[chunkDWords]*/, uint32_t *Y/*[chunkDWords]*/, uint32_t *V/*[chunkDWords * N]*/, uint32_t N, uint32_t r);
#endif

static void STDCALL
scrypt_romix_nop(uint32_t *blocks, size_t nblocks) {
}

static void STDCALL
scrypt_romix_convert_endian(uint32_t *blocks, size_t nblocks) {
#if !defined(CPU_LE)
	static const union { uint8_t b[2]; uint16_t w; } endian_test = {{1,0}};
	size_t i;
	if (endian_test.w == 0x100) {
		nblocks *= SCRYPT_BLOCK_DWORDS;
		for (i = 0; i < nblocks; i++)
			U32_SWAP(blocks[i]);
	}
#endif
}

typedef void (STDCALL *chunkmixfn)(uint32_t *Bout/*[chunkDWords]*/, uint32_t *Bin/*[chunkDWords]*/, uint32_t *Bxor/*[chunkDWords]*/, uint32_t r);
typedef void (STDCALL *blockfixfn)(uint32_t *blocks, size_t nblocks);

static int
scrypt_test_mix_instance(chunkmixfn mixfn, blockfixfn prefn, blockfixfn postfn, const uint8_t expected[16]) {
	const uint32_t r = 2;
	uint32_t MM16 chunk[2][64], v;
	uint8_t final[16];
	size_t i;

	for (i = 0; i < 64; i++) {
		v = (uint32_t)i;
		v = (v << 8) | v;
		v = (v << 16) | v;
		chunk[0][i] = v;
	}

	prefn(chunk[0], r * 2);
	mixfn(chunk[1], chunk[0], NULL, r);
	postfn(chunk[1], r * 2);

	U32TO8_LE(final + 0, chunk[1][60]);
	U32TO8_LE(final + 4, chunk[1][61]);
	U32TO8_LE(final + 8, chunk[1][62]);
	U32TO8_LE(final + 12, chunk[1][63]);

	return scrypt_verify(expected, final, 16);
}

#if defined(SCRYPT_CHACHA)
#include "scrypt-jane-chacha.h"
#elif defined(SCRYPT_SALSA)
#include "scrypt-jane-salsa.h"
#else
	#define SCRYPT_MIX_BASE "ERROR"
	#define SCRYPT_BLOCK_BYTES 64
	#define SCRYPT_BLOCK_DWORDS (SCRYPT_BLOCK_BYTES / sizeof(uint32_t))
	#if !defined(SCRYPT_CHOOSE_COMPILETIME)
		static void FASTCALL scrypt_ROMix_error(uint32_t *X/*[chunkDWords]*/, uint32_t *Y/*[chunkDWords]*/, uint32_t *V/*[chunkDWords * N]*/, uint32_t N, uint32_t r) {}
		static scrypt_ROMixfn scrypt_getROMix() { return scrypt_ROMix_error; }
	#else
		static void FASTCALL scrypt_ROMix(uint32_t *X, uint32_t *Y, uint32_t *V, uint32_t N, uint32_t r) {}
	#endif
	static int scrypt_test_mix() { return 0; }
	#error must define a mix function!
#endif

#if !defined(SCRYPT_CHOOSE_COMPILETIME)
#undef SCRYPT_MIX
#define SCRYPT_MIX SCRYPT_MIX_BASE
#endif
