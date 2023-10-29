HEADERS = bloom.h crack.h hash160.h warpwallet.h
OBJ_MAIN = brainflayer.o hex2blf.o blfchk.o ecmtabgen.o hexln.o sha256ln.o ffrngln.o filehex.o oneoff.o hash2addr.o addr2hash.o
OBJ_UTIL = hex.o bloom.o mmapf.o hsearchf.o ec_pubkey_fast.o dldummy.o b58/b58.o scrypt-jane/scrypt-jane.o
OBJ_ALGO = $(patsubst %.c,%.o,$(wildcard algo/*.c))
OBJ_SHA256 = sha256/sha256.o
ifeq ($(shell uname -m),x86_64)
    OBJ_SHA256 += sha256/sha256-nayuki64-asm.o \
                  sha256/sha256-ssse3-asm.o \
                  sha256/sha256-avx-asm.o \
                  sha256/sha256-avx2-asm.o \
                  sha256/sha256-ni-asm.o
endif
OBJECTS = $(OBJ_MAIN) $(OBJ_UTIL) $(OBJ_ALGO) $(OBJ_SHA256)
BINARIES = brainflayer hexln sha256ln hex2blf blfchk ecmtabgen ffrngln filehex oneoff hash2addr addr2hash
LIBS = -lrt -lcrypto -lz -lgmp -lpthread
override CFLAGS += -O3 \
         -flto -funsigned-char -falign-functions=16 -falign-loops=16 -falign-jumps=16 \
         -Wall -Wextra -Wno-pointer-sign -Wno-sign-compare \
         -pedantic -std=gnu99 -ggdb
COMPILE = gcc $(CFLAGS)

all: $(BINARIES)

.git:
	@echo 'This does not look like a cloned git repo. Unable to fetch submodules.'
	@false

submodule: .git
	git submodule init
	git submodule update

.git/modules/secp256k1: submodule

sha256/sha256-%-asm.o: sha256/sha256-%-asm.S sha256/sha256-%-stub.S
	$(COMPILE) -c $< -o $@ >/dev/null 2>/dev/null || $(COMPILE) -c $(subst asm,stub,$<) -o $@

sha256/sha256.o: sha256/sha256.c sha256/ripemd160_fast.c sha256/ripemd160_small.c sha256/ripemd160_asm.c sha256/sha256_xform.c sha256/sha256_reg.c

secp256k1/.libs/libsecp256k1.a:
	git submodule init
	git submodule update
	cd secp256k1; make distclean || true
	cd secp256k1; ./autogen.sh
	cd secp256k1; ./configure
	cd secp256k1; make

secp256k1/include/secp256k1.h: secp256k1/.libs/libsecp256k1.a

scrypt-jane/scrypt-jane.h: submodule

scrypt-jane/scrypt-jane.o: scrypt-jane/scrypt-jane.h scrypt-jane/scrypt-jane.c
	cd scrypt-jane; gcc -O3 -fPIE -DSCRYPT_SALSA -DSCRYPT_SHA256 -c scrypt-jane.c -o scrypt-jane.o

brainflayer.o: brainflayer.c secp256k1/include/secp256k1.h

algo/warpwallet.o: algo/warpwallet.c scrypt-jane/scrypt-jane.h

algo/brainwalletio.o: algo/brainwalletio.c scrypt-jane/scrypt-jane.h

algo/brainv2.o: algo/brainv2.c scrypt-jane/scrypt-jane.h

ec_pubkey_fast.o: ec_pubkey_fast.c secp256k1/include/secp256k1.h
	$(COMPILE) -Wno-unused-function -c $< -o $@

%.o: %.c
	$(COMPILE) -c $< -o $@

hexln: hexln.o hex.o
	$(COMPILE) $^ $(LIBS) -o $@

hexpdln: hexpdln.o hex.o
	$(COMPILE) $^ $(LIBS) -o $@

p2shln: p2shln.o hex.o $(OBJ_SHA256)
	$(COMPILE) $^ $(LIBS) -o $@

sha256ln: sha256ln.o hex.o $(OBJ_SHA256)
	$(COMPILE) $^ $(LIBS) -o $@

sha256/bench: sha256/bench.o $(OBJ_SHA256)
	$(COMPILE) $^ $(LIBS) -o $@

sha256/grind: sha256/grind.o $(OBJ_SHA256)
	$(COMPILE) $^ $(LIBS) -o $@

blfchk: blfchk.o hex.o bloom.o mmapf.o hsearchf.o
	$(COMPILE) $^ $(LIBS) -o $@

hex2blf: hex2blf.o hex.o bloom.o mmapf.o
	$(COMPILE) $^ $(LIBS) -lm -o $@

ecmtabgen: ecmtabgen.o mmapf.o ec_pubkey_fast.o
	$(COMPILE) $^ $(LIBS) -lm -o $@

ffrngln: ffrngln.o ffrng.o hex.o
	$(COMPILE) $^ $(LIBS) -o $@

filehex: filehex.o hex.o
	$(COMPILE) $^ $(LIBS) -o $@

swab256: swab256.o hex.o
	$(COMPILE) $^ $(LIBS) -o $@

oneoff: oneoff.o hex.o mmapf.o ec_pubkey_fast.o secp256k1/.libs/libsecp256k1.a
	$(COMPILE) $^ $(LIBS) -o $@

brainflayer: brainflayer.o $(OBJ_UTIL) $(OBJ_ALGO) $(OBJ_SHA256) \
             secp256k1/.libs/libsecp256k1.a scrypt-jane/scrypt-jane.o
	$(COMPILE) $^ $(LIBS) -o $@

hash2addr: hash2addr.o hex.o b58/b58.o $(OBJ_SHA256)
	$(COMPILE) $^ $(LIBS) -o $@

addr2hash: addr2hash.o hex.o b58/b58.o $(OBJ_SHA256)
	$(COMPILE) $^ $(LIBS) -o $@

clean:
	rm -f $(BINARIES) $(OBJECTS) *.o
