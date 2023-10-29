#define ENTRY(name) \
        .globl name; \
        .align 4,0x90; \
        name:

#define ENDPROC(name) \
        .type name, @function; \

.text
.align 32
ENTRY(sha256_xform_nayuki64)
	ret
ENDPROC(sha256_xform_nayuki64)

ENTRY(sha256_nayuki64_built)
    xor %eax,%eax
    ret
ENDPROC(sha256_nayuki64_built)
