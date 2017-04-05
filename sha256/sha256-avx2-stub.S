#define ENTRY(name) \
        .globl name; \
        .align 4,0x90; \
        name:

#define ENDPROC(name) \
        .type name, @function; \

.text
.align 32
ENTRY(sha256_transform_rorx)
	ret
ENDPROC(sha256_transform_rorx)

ENTRY(sha256_rorx_built)
    xor %eax,%eax
    ret
ENDPROC(sha256_rorx_built)
