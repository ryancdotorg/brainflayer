#define ENTRY(name) \
        .globl name; \
        .align 4,0x90; \
        name:

#define ENDPROC(name) \
        .type name, @function; \

.text
.align 32
ENTRY(sha256_transform_avx)
	ret
ENDPROC(sha256_transform_avx)

ENTRY(sha256_avx_built)
    xor %eax,%eax
    ret
ENDPROC(sha256_avx_built)
