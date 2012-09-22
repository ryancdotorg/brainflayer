/* basic block operations */
static void INLINE
scrypt_copy_basic(uint32_t *dst, const uint32_t *src, size_t len) {
	for (; len > 0; len -= 4, dst += 4, src += 4) {
		dst[0] = src[0];
		dst[1] = src[1];
		dst[2] = src[2];
		dst[3] = src[3];
	}
}

static void INLINE
scrypt_xor_basic(uint32_t *dst, const uint32_t *src, size_t len) {
	for (; len > 0; len -= 4, dst += 4, src += 4) {
		dst[0] ^= src[0];
		dst[1] ^= src[1];
		dst[2] ^= src[2];
		dst[3] ^= src[3];
	}
}

static void INLINE
scrypt_block_copy_basic(uint32_t *dst, const uint32_t *src) {
	scrypt_copy_basic(dst, src, SCRYPT_BLOCK_DWORDS);
}

static void INLINE
scrypt_block_xor_basic(uint32_t *dst, const uint32_t *src) {
	scrypt_xor_basic(dst, src, SCRYPT_BLOCK_DWORDS);
}

/* returns a pointer to item i, where item is len uint32_t's long */
static uint32_t *
scrypt_item(uint32_t *base, uint32_t i, uint32_t len) {
	return base + (i * len);
}

/* returns a pointer to block i */
static uint32_t *
scrypt_block(uint32_t *base, uint32_t i) {
	return base + (i * SCRYPT_BLOCK_DWORDS);
}
