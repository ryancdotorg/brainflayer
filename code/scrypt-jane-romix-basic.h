/* basic block operations */
static void INLINE
scrypt_copy_basic(uint8_t *dst, const uint8_t *src, size_t len) {
	const size_t *s = (const size_t *)src;
	size_t *d = (size_t *)dst;
	for (len /= (sizeof(size_t) * 4); len; len--, d += 4, s += 4) {
		d[0] = s[0];
		d[1] = s[1];
		d[2] = s[2];
		d[3] = s[3];
	}
}

static void INLINE
scrypt_xor_basic(uint8_t *dst, const uint8_t *src, size_t len) {
	const size_t *s = (const size_t *)src;
	size_t *d = (size_t *)dst;
	for (len /= (sizeof(size_t) * 4); len; len--, d += 4, s += 4) {
		d[0] ^= s[0];
		d[1] ^= s[1];
		d[2] ^= s[2];
		d[3] ^= s[3];
	}
}

static void INLINE
scrypt_block_copy_basic(uint8_t *dst, const uint8_t *src) {
	scrypt_copy_basic(dst, src, SCRYPT_BLOCK_BYTES);
}

static void INLINE
scrypt_block_xor_basic(uint8_t *dst, const uint8_t *src) {
	scrypt_xor_basic(dst, src, SCRYPT_BLOCK_BYTES);
}

/* returns a pointer to item i, where item is len bytes long */
static uint8_t *
scrypt_item(uint8_t *base, uint32_t i, uint32_t len) {
	return base + (i * len);
}

/* returns a pointer to block i */
static uint8_t *
scrypt_block(uint8_t *base, uint32_t i) {
	return base + (i * SCRYPT_BLOCK_BYTES);
}
