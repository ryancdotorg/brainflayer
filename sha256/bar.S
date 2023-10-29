// rdi, rsi, rdx, rcx, r8, r9; ret rax

#define TMP1 r8d

#define F1(x, y, z, r) \
	movl  %x, %r  ;\
	xorl  %y, %r  ;\
	xorl  %z, %r  ;

#define F2(x, y, z, r)  \
	movl  %z, %TMP1;\
	movl  %y, %r   ;\
	xorl  %TMP1, %r;\
	andl  %x, %r   ;\
	xorl  %TMP1, %r;

#define F3(x, y, z, r) \
	movl    %y, %r;\
	notl    %r    ;\
	orl     %x, %r;\
	xorl    %z, %r;

#define F4(x, y, z, r) F2(z, x, y, r)

#define F5(x, y, z, r) F3(y, z, x, r)

f1: F1(ebx, ecx, edx, eax)
f2: F2(ebx, ecx, edx, eax)
f3: F3(ebx, ecx, edx, eax)
f4: F4(ebx, ecx, edx, eax)
f5: F5(ebx, ecx, edx, eax)
