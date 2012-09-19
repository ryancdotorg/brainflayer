#if !defined(SCRYPT_CHOOSE_COMPILETIME) || !defined(SCRYPT_HAVE_ROMIX)

#if defined(SCRYPT_CHOOSE_COMPILETIME)
#undef SCRYPT_ROMIX_FN
#define SCRYPT_ROMIX_FN scrypt_ROMix
#endif

#undef SCRYPT_HAVE_ROMIX
#define SCRYPT_HAVE_ROMIX

#if !defined(SCRYPT_ROMIX_OVERRIDE_CHUNKMIX)
/*
	Bout = ChunkMix(Bin)

	2*r: number of blocks in the chunk
*/
static void STDCALL
SCRYPT_CHUNKMIX_FN(uint8_t *Bout/*[chunkBytes]*/, uint8_t *Bin/*[chunkBytes]*/, uint32_t r) {
	uint8_t MM16 X[SCRYPT_BLOCK_BYTES];
	uint32_t i, blocksPerChunk = r * 2, half = 0;

	/* 1: X = B_{2r - 1} */
	SCRYPT_BLOCK_COPY_FN(X, scrypt_block(Bin, blocksPerChunk - 1));

	/* 2: for i = 0 to 2r - 1 do */
	for (i = 0; i < blocksPerChunk; i++, half ^= r) {
		/* 3: X = H(X ^ B_i) */
		SCRYPT_BLOCK_XOR_FN(X, scrypt_block(Bin, i));
		SCRYPT_MIX_FN((uint32_t *)X);

		/* 4: Y_i = X */
		/* 6: B'[0..r-1] = Y_even */
		/* 6: B'[r..2r-1] = Y_odd */
		SCRYPT_BLOCK_COPY_FN(scrypt_block(Bout, (i / 2) + half), X);
	}
}
#endif

/*
	X = ROMix(X)

	X: chunk to mix
	Y: scratch chunk
	N: number of rounds
	V[N]: array of chunks to randomly index in to
	2*r: number of blocks in a chunk
*/

static void FASTCALL
SCRYPT_ROMIX_FN(uint8_t *X/*[chunkBytes]*/, uint8_t *Y/*[chunkBytes]*/, uint8_t *V/*[chunkBytes * N]*/, uint32_t N, uint32_t r) {
	uint32_t i, j, chunkBytes = SCRYPT_BLOCK_BYTES * r * 2;

	SCRYPT_ROMIX_TANGLE_FN((uint32_t *)X, r * 2);

	/* 1: X = B */
	/* implicit */

	/* 2: for i = 0 to N - 1 do */
	for (i = 0; i < N; i += 2) {
		/* 3: V_i = X */
		SCRYPT_COPY_FN(scrypt_item(V, i, chunkBytes), X, chunkBytes);

		/* 4: Y = H(X) */
		SCRYPT_CHUNKMIX_FN(Y, X, r);

		/* 3: V_i = Y */
		SCRYPT_COPY_FN(scrypt_item(V, i + 1, chunkBytes), Y, chunkBytes);

		/* 4: X = H(Y) */
		SCRYPT_CHUNKMIX_FN(X, Y, r);
	}

	/* 6: for i = 0 to N - 1 do */
	for (i = 0; i < N; i += 2) {
		/* 7: j = Integerify(X) % N */
		j = U8TO32_LE(X + (chunkBytes - SCRYPT_BLOCK_BYTES)) & (N - 1);

		/* 8: Y = H(X ^ V_j) */
		SCRYPT_XOR_FN(X, scrypt_item(V, j, chunkBytes), chunkBytes);
		SCRYPT_CHUNKMIX_FN(Y, X, r);

		/* 7: j = Integerify(Y) % N */
		j = U8TO32_LE(Y + (chunkBytes - SCRYPT_BLOCK_BYTES)) & (N - 1);

		/* 8: X = H(Y ^ V_j) */
		SCRYPT_XOR_FN(Y, scrypt_item(V, j, chunkBytes), chunkBytes);
		SCRYPT_CHUNKMIX_FN(X, Y, r);
	}

	/* 10: B' = X */
	/* implicit */

	SCRYPT_ROMIX_UNTANGLE_FN((uint32_t *)X, r * 2);
}

#endif /* !defined(SCRYPT_CHOOSE_COMPILETIME) || !defined(SCRYPT_HAVE_ROMIX) */


#undef SCRYPT_CHUNKMIX_FN
#undef SCRYPT_ROMIX_FN
#undef SCRYPT_BLOCK_COPY_FN
#undef SCRYPT_BLOCK_XOR_FN
#undef SCRYPT_COPY_FN
#undef SCRYPT_XOR_FN
#undef SCRYPT_MIX_FN
#undef SCRYPT_ROMIX_TANGLE_FN
#undef SCRYPT_ROMIX_UNTANGLE_FN
#undef SCRYPT_ROMIX_OVERRIDE_CHUNKMIX
