HEADERS = bloom.h crack.h hash160.h warpwallet.h
OBJ_MAIN = brainflayer.o hex2blf.o blfchk.o ecmtabgen.o hexln.o filehex.o
OBJ_UTIL = hex.o bloom.o mmapf.o hsearchf.o ec_pubkey_fast.o ripemd160_256.o dldummy.o
OBJ_ALGO = $(patsubst %.c,%.o,$(wildcard algo/*.c))
OBJECTS = $(OBJ_MAIN) $(OBJ_UTIL) $(OBJ_ALGO)
BINARIES = brainflayer hexln hex2blf blfchk ecmtabgen filehex
LIBS = -lrt -lcrypto -lgmp
CFLAGS = -O3 \
         -flto -funsigned-char -falign-functions=16 -falign-loops=16 -falign-jumps=16 \
         -Wall -Wextra -Wno-pointer-sign -Wno-sign-compare \
         -pedantic -std=gnu99
COMPILE = gcc $(CFLAGS)

all: $(BINARIES)

.git:
	@echo 'This does not look like a cloned git repo. Unable to fetch submodules.'
	@false

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
	$(COMPILE) $^ $(LIBS) -o $@

blfchk: blfchk.o hex.o bloom.o mmapf.o hsearchf.o
	$(COMPILE) $^ $(LIBS) -o $@

hex2blf: hex2blf.o hex.o bloom.o mmapf.o
	$(COMPILE) $^ $(LIBS) -lm -o $@

ecmtabgen: ecmtabgen.o mmapf.o ec_pubkey_fast.o
	$(COMPILE) $^ $(LIBS) -o $@

filehex: filehex.o hex.o
	$(COMPILE) $^ $(LIBS) -o $@

brainflayer: brainflayer.o $(OBJ_UTIL) $(OBJ_ALGO) \
             secp256k1/.libs/libsecp256k1.a scrypt-jane/scrypt-jane.o
	$(COMPILE) $^ $(LIBS) -o $@

clean:
	rm -f $(BINARIES) $(OBJECTS)
