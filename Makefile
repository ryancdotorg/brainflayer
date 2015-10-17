HEADERS = bloom.h crack.h hash160.h warpwallet.h
OBJECTS = brainflayer.o bloom.o hex2blf.o warpwallet.o hex.o mmapf.o
BINARIES = brainflayer hex2blf blfchk ecmtabgen
LIBS = -lssl -lrt -lcrypto -lz -ldl -lgmp
CFLAGS = -O3 -flto -pedantic -std=gnu99 -Wall -Wextra -funsigned-char -Wno-pointer-sign -Wno-sign-compare
COMPILE = gcc $(CFLAGS)

all: $(BINARIES)

secp256k1/.libs/libsecp256k1.a:
	git submodule init
	git submodule update
	cd secp256k1; make distclean || true
	cd secp256k1; ./autogen.sh
	cd secp256k1; ./configure
	cd secp256k1; make

secp256k1/include/secp256k1.h: secp256k1/.libs/libsecp256k1.a

scrypt-jane/scrypt-jane.h:
	git submodule init
	git submodule update

scrypt-jane/scrypt-jane.o: scrypt-jane/scrypt-jane.h scrypt-jane/scrypt-jane.c
	cd scrypt-jane; gcc -O3 -DSCRYPT_SALSA -DSCRYPT_SHA256 -c scrypt-jane.c -o scrypt-jane.o

brainflayer.o: brainflayer.c secp256k1/include/secp256k1.h

warpwallet.o: warpwallet.c scrypt-jane/scrypt-jane.h

brainwalletio.o: brainwalletio.c scrypt-jane/scrypt-jane.h

ec_pubkey_fast.o: ec_pubkey_fast.c secp256k1/include/secp256k1.h
	$(COMPILE) -Wno-unused-function -c $< -o $@

%.o: %.c
	$(COMPILE) -c $< -o $@

blfchk: blfchk.o hex.o bloom.o mmapf.o
	$(COMPILE) -static $^ $(LIBS) -o $@

hex2blf: hex2blf.o hex.o bloom.o mmapf.o
	$(COMPILE) -static $^ $(LIBS) -o $@

ecmtabgen: ecmtabgen.o mmapf.o ec_pubkey_fast.o secp256k1/.libs/libsecp256k1.a
	$(COMPILE) -static $^ $(LIBS) -o $@

brainflayer: brainflayer.o hex.o bloom.o mmapf.o warpwallet.o brainwalletio.o brainv2.o ec_pubkey_fast.o secp256k1/.libs/libsecp256k1.a scrypt-jane/scrypt-jane.o
	$(COMPILE) -static $^ $(LIBS) -o $@

clean:
	rm -f $(BINARIES) $(OBJECTS)
