#define ENTRY(name) \
        .globl name; \
        .align 4,0x90; \
        name:

#define ENDPROC(name) \
        .type name, @function; \

.text
.align 32
ENTRY(sha256_transform_ssse3)
	ret
ENDPROC(sha256_transform_ssse3)

ENTRY(sha256_ssse3_built)
    xor %eax,%eax
    ret
ENDPROC(sha256_ssse3_built)
