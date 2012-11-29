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
