HEADERS = bloom.h crack.h hash160.h warpwallet.h
OBJECTS = brainflayer.o bloom.o hex2blf.o
BINARIES = brainflayer hex2blf
LIBS = -lssl -lrt -lcrypto -lz -ldl -lgmp
CFLAGS = -O2
COMPILE = gcc $(CFLAGS) -g -pedantic -std=gnu99 -Wall -Wextra -funsigned-char -Wno-pointer-sign -Wno-sign-compare

secp256k1/.libs/libsecp256k1.a:
	git submodule init
	git submodule update
	cd secp256k1; make distclean || true
	cd secp256k1; ./autogen.sh
	cd secp256k1; ./configure
	cd secp256k1; make

secp256k1/include/secp256k1.h: secp256k1/.libs/libsecp256k1.a

libscrypt/libscrypt.a:
	git submodule init
	git submodule update
	cd libscrypt; make

libscrypt/libscrypt.a: libscrypt/libscrypt.h

brainflayer.o: brainflayer.c secp256k1/include/secp256k1.h

%.o: %.c
	$(COMPILE) -c $< -o $@

hex2blf: hex2blf.o bloom.o
	$(COMPILE) -static $^ $(LIBS) -o $@

brainflayer: brainflayer.o bloom.o warpwallet.o secp256k1/.libs/libsecp256k1.a
	$(COMPILE) -static $^ $(LIBS) -o $@


all: $(BINARIES)

clean:
	rm -f $(BINARIES) $(OBJECTS)
