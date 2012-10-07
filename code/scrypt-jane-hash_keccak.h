#if defined(SCRYPT_KECCAK256)
	#define SCRYPT_HASH "Keccak-256"
	#define SCRYPT_HASH_DIGEST_SIZE 32
#else
	#define SCRYPT_HASH "Keccak-512"
	#define SCRYPT_HASH_DIGEST_SIZE 64
#endif
#define SCRYPT_KECCAK_F 1600
#define SCRYPT_KECCAK_C (SCRYPT_HASH_DIGEST_SIZE * 8 * 2) /* 256=512, 512=1024 */
#define SCRYPT_KECCAK_R (SCRYPT_KECCAK_F - SCRYPT_KECCAK_C) /* 256=1088, 512=576 */
#define SCRYPT_HASH_BLOCK_SIZE (SCRYPT_KECCAK_R / 8)

typedef uint8_t scrypt_hash_digest[SCRYPT_HASH_DIGEST_SIZE];

typedef struct scrypt_hash_state_t {
	uint64_t state[SCRYPT_KECCAK_F / 64];
	uint32_t leftover;
	uint8_t buffer[SCRYPT_HASH_BLOCK_SIZE];
} scrypt_hash_state;

static const uint64_t keccak_round_constants[24] = {
	0x0000000000000001ull, 0x0000000000008082ull, 0x800000000000808aull,
	0x8000000080008000ull, 0x000000000000808bull, 0x0000000080000001ull,
	0x8000000080008081ull, 0x8000000000008009ull, 0x000000000000008aull,
	0x0000000000000088ull, 0x0000000080008009ull, 0x000000008000000aull,
	0x000000008000808bull, 0x800000000000008bull, 0x8000000000008089ull,
	0x8000000000008003ull, 0x8000000000008002ull, 0x8000000000000080ull,
	0x000000000000800aull, 0x800000008000000aull, 0x8000000080008081ull,
	0x8000000000008080ull, 0x0000000080000001ull, 0x8000000080008008ull
};

static const uint8_t keccak_rotation_constants[24] = {
	1,3,6,10,15,21,28,36,45,55,2,14,27,41,56,8,25,43,62,18,39,61,20,44
};

const uint8_t keccak_pilane_constants[24] = {
	10,7,11,17,18,3,5,16,8,21,24,4,15,23,19,13,12,2,20,14,22,9,6,1
};

const uint8_t keccak_mod5[10] = {
    0,1,2,3,4,0,1,2,3,4
};

static void
keccak_block(scrypt_hash_state *S, const uint8_t *in) {
	size_t r, i, j;
	uint64_t *s = S->state, t[5], u, v;

	/* absorb input */
	for (i = 0; i < SCRYPT_HASH_BLOCK_SIZE / 8; i++, in += 8)
		s[i] ^= U8TO64_LE(in);
	
	for (r = 0; r < 24; r++) {
		/* theta: c */
		for (i = 0; i < 5; i++)
			t[i] = s[i] ^ s[i + 5] ^ s[i + 10] ^ s[i + 15] ^ s[i + 20];

		/* theta: a ^= d */
		for (i = 0; i < 5; i++) {
			u = t[keccak_mod5[i + 4]] ^ ROTL64(t[keccak_mod5[i + 1]], 1);
			for (j = 0; j < 25; j += 5)
				s[j + i] ^= u;
		}

		/* rho pi: b */
		u = s[1];
		for (i = 0; i < 24; i++) {
			v = s[keccak_pilane_constants[i]];
			s[keccak_pilane_constants[i]] = ROTL64(u, keccak_rotation_constants[i]);
			u = v;
		}

		/* chi: a */
		for (i = 0; i < 25; i += 5) {
			for (j = 0; j < 5; j++)
				t[j] = s[i + j];
			for (j = 0; j < 5; j++)
				s[i + j] = t[j] ^ ((~t[keccak_mod5[j + 1]]) & t[keccak_mod5[j + 2]]);
		}
		
		/* iota: round constant */
		s[0] ^= keccak_round_constants[r];
	}
}

static void
scrypt_hash_init(scrypt_hash_state *S) {
	memset(S, 0, sizeof(*S));
}

static void
scrypt_hash_update(scrypt_hash_state *S, const uint8_t *in, size_t inlen) {
	size_t want;

	/* handle the previous data */
	if (S->leftover) {
		want = (SCRYPT_HASH_BLOCK_SIZE - S->leftover);
		want = (want < inlen) ? want : inlen;
		memcpy(S->buffer + S->leftover, in, want);
		S->leftover += (uint32_t)want;
		if (S->leftover < SCRYPT_HASH_BLOCK_SIZE)
			return;
		in += want;
		inlen -= want;
		keccak_block(S, S->buffer);
	}

	/* handle the current data */
	while (inlen >= SCRYPT_HASH_BLOCK_SIZE) {
		keccak_block(S, in);
		in += SCRYPT_HASH_BLOCK_SIZE;
		inlen -= SCRYPT_HASH_BLOCK_SIZE;
	}

	/* handle leftover data */
	S->leftover = (uint32_t)inlen;
	if (S->leftover)
		memcpy(S->buffer, in, S->leftover);
}

static void
scrypt_hash_finish(scrypt_hash_state *S, uint8_t *hash) {
	size_t i;

	S->buffer[S->leftover] = 0x01;
	memset(S->buffer + (S->leftover + 1), 0, SCRYPT_HASH_BLOCK_SIZE - (S->leftover + 1));
	S->buffer[SCRYPT_HASH_BLOCK_SIZE - 1] |= 0x80;
	keccak_block(S, S->buffer);

	for (i = 0; i < SCRYPT_HASH_DIGEST_SIZE; i += 8) {
		U64TO8_LE(&hash[i], S->state[i / 8]);
	}
}

#if defined(SCRYPT_KECCAK256)
static const uint8_t scrypt_test_hash_expected[SCRYPT_HASH_DIGEST_SIZE] = {
	0x26,0xb7,0x10,0xb3,0x66,0xb1,0xd1,0xb1,0x25,0xfc,0x3e,0xe3,0x1e,0x33,0x1d,0x19,
	0x94,0xaa,0x63,0x7a,0xd5,0x77,0x29,0xb4,0x27,0xe9,0xe0,0xf4,0x19,0xba,0x68,0xea,
};
#else
static const uint8_t scrypt_test_hash_expected[SCRYPT_HASH_DIGEST_SIZE] = {
	0x17,0xc7,0x8c,0xa0,0xd9,0x08,0x1d,0xba,0x8a,0xc8,0x3e,0x07,0x90,0xda,0x91,0x88,
	0x25,0xbd,0xd3,0xf8,0x78,0x4a,0x8d,0x5e,0xe4,0x96,0x9c,0x01,0xf3,0xeb,0xdc,0x12,
	0xea,0x35,0x57,0xba,0x94,0xb8,0xe9,0xb9,0x27,0x45,0x0a,0x48,0x5c,0x3d,0x69,0xf0,
	0xdb,0x22,0x38,0xb5,0x52,0x22,0x29,0xea,0x7a,0xb2,0xe6,0x07,0xaa,0x37,0x4d,0xe6,
};
#endif

