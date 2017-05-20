HEADERS = bloom.h crack.h hash160.h warpwallet.h
OBJ_MAIN = brainflayer.o hex2blf.o blfchk.o ecmtabgen.o hexln.o sha256ln.o filehex.o
OBJ_UTIL = hex.o bloom.o mmapf.o hsearchf.o ec_pubkey_fast.o dldummy.o
OBJ_ALGO = $(patsubst %.c,%.o,$(wildcard algo/*.c))
OBJ_SHA256 = sha256/sha256.o
ifeq ($(shell uname -m),x86_64)
    OBJ_SHA256 += sha256/sha256-avx-asm.o sha256/sha256-avx2-asm.o sha256/sha256-ssse3-asm.o sha256/sha256-ni-asm.o
endif
OBJECTS = $(OBJ_MAIN) $(OBJ_UTIL) $(OBJ_ALGO) $(OBJ_SHA256)
BINARIES = brainflayer hexln sha256ln hex2blf blfchk ecmtabgen filehex
LIBS = -lrt -lcrypto -lz -lgmp
CFLAGS = -O3 \
         -flto -funsigned-char -falign-functions=16 -falign-loops=16 -falign-jumps=16 \
         -Wall -Wextra -Wno-pointer-sign -Wno-sign-compare \
         -pedantic -std=gnu99
COMPILE = gcc $(CFLAGS)

all: $(BINARIES)

.git:
	@echo 'This does not look like a cloned git repo. Unable to fetch submodules.'
	@false

sha256/sha256-%-asm.o: sha256/sha256-%-asm.S sha256/sha256-%-stub.S
	$(COMPILE) -c $< -o $@ >/dev/null 2>/dev/null || $(COMPILE) -c $(subst asm,stub,$<) -o $@

sha256/sha256.o: sha256/sha256.c sha256/ripemd160.c sha256/sha256_xform.c sha256/sha256_reg.c

secp256k1/.libs/libsecp256k1.a: .git
	git submodule init
	git submodule update
	cd secp256k1; make distclean || true
	cd secp256k1; ./autogen.sh
	cd secp256k1; ./configure
	cd secp256k1; make

secp256k1/include/secp256k1.h: secp256k1/.libs/libsecp256k1.a

scrypt-jane/scrypt-jane.h: .git
	git submodule init
	git submodule update

scrypt-jane/scrypt-jane.o: scrypt-jane/scrypt-jane.h scrypt-jane/scrypt-jane.c
	cd scrypt-jane; gcc -O3 -DSCRYPT_SALSA -DSCRYPT_SHA256 -c scrypt-jane.c -o scrypt-jane.o

brainflayer.o: brainflayer.c secp256k1/include/secp256k1.h

algo/warpwallet.o: algo/warpwallet.c scrypt-jane/scrypt-jane.h

algo/brainwalletio.o: algo/brainwalletio.c scrypt-jane/scrypt-jane.h

algo/brainv2.o: algo/brainv2.c scrypt-jane/scrypt-jane.h

ec_pubkey_fast.o: ec_pubkey_fast.c secp256k1/include/secp256k1.h
	$(COMPILE) -Wno-unused-function -c $< -o $@

%.o: %.c
	$(COMPILE) -c $< -o $@

hexln: hexln.o hex.o
	$(COMPILE) -static $^ $(LIBS) -o $@

sha256ln: sha256ln.o hex.o $(OBJ_SHA256)
	$(COMPILE) -static $^ $(LIBS) -o $@

blfchk: blfchk.o hex.o bloom.o mmapf.o hsearchf.o
	$(COMPILE) -static $^ $(LIBS) -o $@

hex2blf: hex2blf.o hex.o bloom.o mmapf.o
	$(COMPILE) -static $^ $(LIBS) -lm -o $@

ecmtabgen: ecmtabgen.o mmapf.o ec_pubkey_fast.o
	$(COMPILE) -static $^ $(LIBS) -o $@

filehex: filehex.o hex.o
	$(COMPILE) -static $^ $(LIBS) -o $@

brainflayer: brainflayer.o $(OBJ_UTIL) $(OBJ_ALGO) $(OBJ_SHA256) \
             secp256k1/.libs/libsecp256k1.a scrypt-jane/scrypt-jane.o
	$(COMPILE) -static $^ $(LIBS) -o $@

clean:
	rm -f $(BINARIES) $(OBJECTS)
