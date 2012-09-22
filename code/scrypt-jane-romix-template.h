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
SCRYPT_CHUNKMIX_FN(uint32_t *Bout/*[chunkDWords]*/, uint32_t *Bin/*[chunkDWords]*/, uint32_t r) {
	uint32_t MM16 X[SCRYPT_BLOCK_DWORDS];
	uint32_t i, blocksPerChunk = r * 2, half = 0;

	/* 1: X = B_{2r - 1} */
	SCRYPT_BLOCK_COPY_FN(X, scrypt_block(Bin, blocksPerChunk - 1));

	/* 2: for i = 0 to 2r - 1 do */
	for (i = 0; i < blocksPerChunk; i++, half ^= r) {
		/* 3: X = H(X ^ B_i) */
		SCRYPT_BLOCK_XOR_FN(X, scrypt_block(Bin, i));
		SCRYPT_MIX_FN(X);

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

static void NOINLINE FASTCALL
SCRYPT_ROMIX_FN(uint32_t *X/*[chunkDWords]*/, uint32_t *Y/*[chunkDWords]*/, uint32_t *V/*[N * chunkDWords]*/, uint32_t N, uint32_t r) {
	uint32_t i, j, chunkDWords = SCRYPT_BLOCK_DWORDS * r * 2;

	SCRYPT_ROMIX_TANGLE_FN(X, r * 2);

	/* 1: X = B */
	/* implicit */

	/* 2: for i = 0 to N - 1 do */
	for (i = 0; i < N; i += 2) {
		/* 3: V_i = X */
		SCRYPT_COPY_FN(scrypt_item(V, i, chunkDWords), X, chunkDWords);

		/* 4: Y = H(X) */
		SCRYPT_CHUNKMIX_FN(Y, X, r);

		/* 3: V_i = Y */
		SCRYPT_COPY_FN(scrypt_item(V, i + 1, chunkDWords), Y, chunkDWords);

		/* 4: X = H(Y) */
		SCRYPT_CHUNKMIX_FN(X, Y, r);
	}

	/* 6: for i = 0 to N - 1 do */
	for (i = 0; i < N; i += 2) {
		/* 7: j = Integerify(X) % N */
		j = X[chunkDWords - SCRYPT_BLOCK_DWORDS] & (N - 1);

		/* 8: Y = H(X ^ V_j) */
		SCRYPT_XOR_FN(X, scrypt_item(V, j, chunkDWords), chunkDWords);
		SCRYPT_CHUNKMIX_FN(Y, X, r);

		/* 7: j = Integerify(Y) % N */
		j = Y[chunkDWords - SCRYPT_BLOCK_DWORDS] & (N - 1);

		/* 8: X = H(Y ^ V_j) */
		SCRYPT_XOR_FN(Y, scrypt_item(V, j, chunkDWords), chunkDWords);
		SCRYPT_CHUNKMIX_FN(X, Y, r);
	}

	/* 10: B' = X */
	/* implicit */

	SCRYPT_ROMIX_UNTANGLE_FN(X, r * 2);
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
