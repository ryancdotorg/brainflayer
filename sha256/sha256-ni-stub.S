#define ENTRY(name) \
        .globl name; \
        .align 4,0x90; \
        name:

#define ENDPROC(name) \
        .type name, @function; \

.text
.align 32
ENTRY(sha256_ni_transform)
	ret
ENDPROC(sha256_ni_transform)

ENTRY(sha256_ni_built)
    xor %eax,%eax
    ret
ENDPROC(sha256_ni_built)
